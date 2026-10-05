package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveRejectsTraversalAndLinks(t *testing.T) {
	for _, h := range []*tar.Header{
		{Name: "../escaped", Typeflag: tar.TypeReg},
		{Name: "/tmp/escaped", Typeflag: tar.TypeReg},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../escaped"},
		{Name: "link", Typeflag: tar.TypeLink, Linkname: "../escaped"},
	} {
		t.Run(h.Name+string(h.Typeflag), func(t *testing.T) {
			var archive bytes.Buffer
			w := tar.NewWriter(&archive)
			if err := w.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := extract(t.TempDir(), archive.Bytes()); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestArchivePreservesWASMBytes(t *testing.T) {
	data := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	if err := w.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "61a21670a67c78694e4dd634900075d074a01784"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(&tar.Header{Name: "server/policywasm/allowit_sdk.wasm", Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := extract(root, archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "server/policywasm/allowit_sdk.wasm"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("artifact altered: %x %v", got, err)
	}
}
