// Command integration runs the real CLI against pinned Go gateways in temporary
// archives. It never changes the app checkout or uses live wallet credentials.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type backend struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	Tests    []string `json:"tests"`
}

func main() {
	appRepo := flag.String("app-repo", "", "AllowIt-app clone containing the pinned commits")
	selected := flag.String("backend", "", "optional customer-workspace or typed-skill-runtime")
	flag.Parse()
	if err := check(*appRepo, *selected); err != nil {
		fmt.Fprintln(os.Stderr, "integration:", err)
		os.Exit(1)
	}
}

func check(appRepo, selected string) error {
	if appRepo == "" || flag.NArg() != 0 {
		return errors.New("usage: go run ./integration --app-repo /path/to/AllowIt-app [--backend NAME]")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	appRepo, err = filepath.Abs(appRepo)
	if err != nil {
		return err
	}
	var backends []backend
	if err := readJSON(filepath.Join(root, "integration", "backends.json"), &backends); err != nil {
		return err
	}
	var chosen []backend
	for _, b := range backends {
		if selected == "" || b.Name == selected {
			chosen = append(chosen, b)
		}
	}
	if len(chosen) == 0 {
		return fmt.Errorf("unknown or empty backend selection %q", selected)
	}
	for _, b := range chosen {
		if !filepath.IsLocal(b.Name) || filepath.Base(b.Name) != b.Name {
			return errors.New("invalid backend name")
		}
		if raw, err := hex.DecodeString(b.Revision); err != nil || len(raw) != 20 {
			return errors.New("backend revision must be a full commit SHA")
		}
		actual, err := exec.Command("git", "-C", appRepo, "rev-parse", b.Revision+"^{commit}").Output()
		if err != nil {
			return fmt.Errorf("missing backend commit %s: %w", b.Revision, err)
		}
		if strings.TrimSpace(string(actual)) != b.Revision {
			return errors.New("backend revision must be an exact commit")
		}
	}
	temp, err := os.MkdirTemp("", "allowit-cli-contract-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	binary := filepath.Join(root, "target", "debug", "allowit")
	if override := os.Getenv("ALLOWIT_ALIGNMENT_BINARY"); override != "" {
		binary, err = filepath.Abs(override)
		if err != nil {
			return err
		}
	} else if err := command(root, nil, "cargo", "build", "--locked"); err != nil {
		return err
	}
	for _, b := range chosen {
		if err := checkBackend(root, appRepo, temp, binary, b); err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}
	}
	return nil
}

func checkBackend(root, appRepo, temp, binary string, b backend) error {
	app := filepath.Join(temp, b.Name)
	archive, err := exec.Command("git", "-C", appRepo, "archive", b.Revision, "go.mod", "go.sum", "server").Output()
	if err != nil {
		return err
	}
	if err := extract(app, archive); err != nil {
		return err
	}
	var manifest struct {
		Commit string `json:"commit"`
		SHA256 string `json:"sha256"`
	}
	if err := readJSON(filepath.Join(app, "server", "policywasm", "manifest.json"), &manifest); err != nil {
		return err
	}
	wasm, err := os.ReadFile(filepath.Join(app, "server", "policywasm", "allowit_sdk.wasm"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(wasm)
	actualHash := hex.EncodeToString(digest[:])
	if actualHash != manifest.SHA256 {
		return errors.New("pinned SDK WASM hash mismatch")
	}
	expected := map[string]bool{}
	for _, name := range b.Tests {
		if !filepath.IsLocal(name) || filepath.Base(name) != name || !strings.HasSuffix(name, "_test.go") {
			return errors.New("invalid test filename")
		}
		source := filepath.Join(root, "integration", "testdata", name)
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), source, data, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Recv == nil && strings.HasPrefix(f.Name.Name, "TestAlignment") {
				if expected[f.Name.Name] {
					return fmt.Errorf("duplicate test %s", f.Name.Name)
				}
				expected[f.Name.Name] = true
			}
		}
		if err := os.WriteFile(filepath.Join(app, "server", "app", "alignment_"+name), data, 0600); err != nil {
			return err
		}
	}
	if len(expected) == 0 {
		return errors.New("no integration tests selected")
	}
	fmt.Printf("%s: app %s, SDK %s, WASM %s\n", b.Name, b.Revision, manifest.Commit, actualHash)
	env := append(os.Environ(), "ALLOWIT_ALIGNMENT_BINARY="+binary)
	if err := testGateway(app, env, expected); err != nil {
		return err
	}
	fmt.Printf("Verified %d named integration cases.\n", len(expected))
	return nil
}

// Only regular files and directories from the pinned Git archive are needed.
// Reject traversal and links so extraction cannot write outside its temp root.
func extract(root string, archive []byte) error {
	r := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue // git archive records its commit as PAX metadata, not a file.
		}
		if !filepath.IsLocal(h.Name) {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		path := filepath.Join(root, h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, r)
			closeErr := f.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry %q", h.Name)
		}
	}
}

func testGateway(dir string, env []string, expected map[string]bool) error {
	cmd := exec.Command("go", "test", "-race", "-count=1", "-run", "^TestAlignment", "-json", "./server/app")
	cmd.Dir, cmd.Env, cmd.Stderr = dir, env, os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	passed := map[string]bool{}
	decoder := json.NewDecoder(stdout)
	for {
		var event struct{ Action, Test, Output string }
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("invalid go test event: %w", err)
		}
		fmt.Print(event.Output)
		if event.Action == "pass" && event.Test != "" {
			passed[event.Test] = true
		}
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	var missing []string
	for name := range expected {
		if !passed[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("integration tests did not pass: %s", strings.Join(missing, ", "))
	}
	return nil
}

func command(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, os.Stdout, os.Stderr
	return cmd.Run()
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
