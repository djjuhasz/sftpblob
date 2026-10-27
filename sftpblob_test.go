package sftpblob

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const (
	testUser = "test"
	testPass = "test-password"
)

// sftpAddr is the host:port of the in-process SFTP server used by the tests.
var sftpAddr string

// TestMain starts an in-process SSH server that serves the SFTP subsystem
// from the local filesystem (using github.com/pkg/sftp's server).
func TestMain(m *testing.M) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	sftpAddr = ln.Addr().String()
	go serve(ln)
	code := m.Run()
	ln.Close()
	os.Exit(code)
}

func serve(ln net.Listener) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == testUser && string(pass) == testPass {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	cfg.AddHostKey(signer)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(conn, cfg)
	}
}

func handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	defer nConn.Close()
	_, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				ok := req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp"
				req.Reply(ok, nil)
			}
		}()
		go func() {
			defer ch.Close()
			srv, err := sftp.NewServer(ch)
			if err != nil {
				return
			}
			srv.Serve()
		}()
	}
}

// bucketURL returns an sftp URL for the given credentials and absolute path.
func bucketURL(user, pass, path string) string {
	u := url.URL{
		Scheme: Scheme,
		User:   url.UserPassword(user, pass),
		Host:   sftpAddr,
		Path:   path,
	}
	return u.String()
}

// newBucket opens a bucket rooted in a fresh temp dir.
func newBucket(t *testing.T) *blob.Bucket {
	b, _ := newBucketDir(t)
	return b
}

// newBucketDir is like newBucket but also returns the backing directory.
func newBucketDir(t *testing.T) (*blob.Bucket, string) {
	t.Helper()
	dir := t.TempDir()
	b, err := blob.OpenBucket(context.Background(), bucketURL(testUser, testPass, dir))
	if err != nil {
		t.Fatalf("open bucket: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b, dir
}

func TestOpenBucketBadCredentials(t *testing.T) {
	_, err := blob.OpenBucket(context.Background(), bucketURL(testUser, "wrong", t.TempDir()))
	if err == nil {
		t.Fatal("expected error with bad credentials")
	}
}

func TestOpenBucketMissingDir(t *testing.T) {
	_, err := blob.OpenBucket(context.Background(), bucketURL(testUser, testPass, filepath.Join(t.TempDir(), "nope")))
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestOpenBucketNotADirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := blob.OpenBucket(context.Background(), bucketURL(testUser, testPass, file))
	if err == nil {
		t.Fatal("expected error opening a file as a bucket")
	}
}

func TestWriteReadDelete(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	want := []byte("hello sftp")
	if err := b.WriteAll(ctx, "hello.txt", want, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := b.ReadAll(ctx, "hello.txt")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read %q, want %q", got, want)
	}

	if err := b.Delete(ctx, "hello.txt"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	exists, err := b.Exists(ctx, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("blob still exists after delete")
	}
}

func TestOverwriteTruncates(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	if err := b.WriteAll(ctx, "f", []byte("long original content"), nil); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteAll(ctx, "f", []byte("short"), nil); err != nil {
		t.Fatal(err)
	}
	got, err := b.ReadAll(ctx, "f")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "short" {
		t.Errorf("got %q, want %q", got, "short")
	}
}

func TestWriteCreatesParentDirs(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	if err := b.WriteAll(ctx, "a/b/c/deep.txt", []byte("deep"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := b.ReadAll(ctx, "a/b/c/deep.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "deep" {
		t.Errorf("got %q", got)
	}
}

func TestAttributes(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	data := []byte("0123456789")
	before := time.Now().Add(-time.Minute)
	if err := b.WriteAll(ctx, "attrs.bin", data, nil); err != nil {
		t.Fatal(err)
	}
	attrs, err := b.Attributes(ctx, "attrs.bin")
	if err != nil {
		t.Fatal(err)
	}
	if attrs.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", attrs.Size, len(data))
	}
	if attrs.ModTime.Before(before) {
		t.Errorf("mod time %v is too old", attrs.ModTime)
	}
}

func TestRangeReader(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	if err := b.WriteAll(ctx, "range", []byte("0123456789"), nil); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		offset, length int64
		want           string
	}{
		{"whole", 0, -1, "0123456789"},
		{"offset", 3, -1, "3456789"},
		{"length", 0, 4, "0123"},
		{"offset and length", 2, 5, "23456"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := b.NewRangeReader(ctx, "range", tc.offset, tc.length, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if r.Size() != 10 {
				t.Errorf("reader size = %d, want 10", r.Size())
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	_, err := b.ReadAll(ctx, "missing")
	if code := gcerrors.Code(err); code != gcerrors.NotFound {
		t.Errorf("ReadAll code = %v (err %v), want NotFound", code, err)
	}
	_, err = b.Attributes(ctx, "missing")
	if code := gcerrors.Code(err); code != gcerrors.NotFound {
		t.Errorf("Attributes code = %v (err %v), want NotFound", code, err)
	}
	err = b.Delete(ctx, "missing")
	if code := gcerrors.Code(err); code != gcerrors.NotFound {
		t.Errorf("Delete code = %v (err %v), want NotFound", code, err)
	}
}

func TestDirectoryIsNotABlob(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	if err := b.WriteAll(ctx, "dir/file", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReadAll(ctx, "dir"); gcerrors.Code(err) != gcerrors.NotFound {
		t.Errorf("reading a directory: code = %v (err %v), want NotFound", gcerrors.Code(err), err)
	}
}

func TestCopy(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	want := []byte("copy me")
	if err := b.WriteAll(ctx, "src", want, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Copy(ctx, "nested/dst", "src", nil); err != nil {
		t.Fatalf("copy: %v", err)
	}
	for _, key := range []string{"src", "nested/dst"} {
		got, err := b.ReadAll(ctx, key)
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	err := b.Copy(ctx, "dst2", "missing", nil)
	if code := gcerrors.Code(err); code != gcerrors.NotFound {
		t.Errorf("copy of missing: code = %v (err %v), want NotFound", code, err)
	}
}

func TestDeleteDirectory(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	if err := b.WriteAll(ctx, "d/.newdir", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, "d"); err != nil {
		t.Fatalf("delete dir: %v", err)
	}
	it := b.List(&blob.ListOptions{Delimiter: "/"})
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if obj.Key == "d" {
			t.Error("directory still listed after delete")
		}
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	for _, k := range []string{"b.txt", "a.txt", "sub/c.txt", "sub/d.txt", "zdir/e.txt"} {
		if err := b.WriteAll(ctx, k, []byte(k), nil); err != nil {
			t.Fatal(err)
		}
	}

	list := func(prefix string) []string {
		var keys []string
		it := b.List(&blob.ListOptions{Prefix: prefix, Delimiter: "/"})
		for {
			obj, err := it.Next(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("list %q: %v", prefix, err)
			}
			keys = append(keys, obj.Key)
		}
		return keys
	}

	t.Run("root", func(t *testing.T) {
		got := list("")
		// Directories sort before files.
		want := []string{"sub", "zdir", "a.txt", "b.txt"}
		if !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("subdir", func(t *testing.T) {
		got := list("sub/")
		want := []string{"sub/c.txt", "sub/d.txt"}
		if !equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("object metadata", func(t *testing.T) {
		it := b.List(&blob.ListOptions{Prefix: "sub/", Delimiter: "/"})
		obj, err := it.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if obj.Size != int64(len("sub/c.txt")) {
			t.Errorf("size = %d", obj.Size)
		}
		if obj.IsDir {
			t.Error("file reported as dir")
		}
	})
}

func TestAs(t *testing.T) {
	b := newBucket(t)

	var c *sftp.Client
	if !b.As(&c) || c == nil {
		t.Fatal("As(**sftp.Client) failed")
	}
	if _, err := c.Getwd(); err != nil {
		t.Errorf("client unusable: %v", err)
	}

	var s string
	if b.As(&s) {
		t.Error("As(*string) should return false")
	}
}

func TestErrorAs(t *testing.T) {
	ctx := context.Background()
	b := newBucket(t)

	_, err := b.ReadAll(ctx, "missing")
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *os.PathError
	if !b.ErrorAs(err, &pe) {
		t.Fatalf("ErrorAs(*os.PathError) = false for error %T", err)
	}
	if pe.Path == "" {
		t.Error("PathError has empty path")
	}
}

func TestSignedURLNotImplemented(t *testing.T) {
	b := newBucket(t)
	_, err := b.SignedURL(context.Background(), "k", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCancelledWrite(t *testing.T) {
	b := newBucket(t)

	ctx, cancel := context.WithCancel(context.Background())
	w, err := b.NewWriter(ctx, "cancelled", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := w.Close(); err == nil {
		t.Error("expected error closing writer with cancelled context")
	}
}

func TestAddTrailingSlash(t *testing.T) {
	for in, want := range map[string]string{
		"":       "/",
		"/":      "/",
		"/a":     "/a/",
		"/a/b/":  "/a/b/",
		"/a/b/c": "/a/b/c/",
	} {
		if got := addTrailingSlash(in); got != want {
			t.Errorf("addTrailingSlash(%q) = %q, want %q", in, got, want)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
