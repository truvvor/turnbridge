// SPDX-License-Identifier: MIT
//
// Captcha trap ("мухоловка"): buffers every captcha challenge in memory
// while the solver runs and flushes the buffer to disk ONLY if the solve
// ultimately fails. Successful solves leave nothing behind. Failed
// solves drop a self-contained folder (raw VK response JSON, the image
// bytes, a notes log) into the App Group container so we can inspect
// captcha variants we don't yet handle.
//
// Wiring: Swift creates the trap directory under the App Group container
// and pushes the absolute path here via TurnBridgeSetCaptchaTrapDir
// before StartProxy. If the path is empty, every trap call is a no-op
// (the feature simply doesn't engage).

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	captchaTrapDir atomic.Value // string
)

//export TurnBridgeSetCaptchaTrapDir
func TurnBridgeSetCaptchaTrapDir(cPath *C.char) {
	if cPath == nil {
		captchaTrapDir.Store("")
		return
	}
	path := C.GoString(cPath)
	captchaTrapDir.Store(path)
	if path == "" {
		log.Printf("captcha-trap: disabled (empty path)")
		return
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		log.Printf("captcha-trap: mkdir %q failed: %v — feature off", path, err)
		captchaTrapDir.Store("")
		return
	}
	log.Printf("captcha-trap: artifacts → %s", path)
}

func captchaTrapRoot() string {
	v, _ := captchaTrapDir.Load().(string)
	return v
}

type captchaTrap struct {
	label   string
	started time.Time

	mu      sync.Mutex
	files   map[string][]byte
	notes   []string
	flushed bool
}

// newCaptchaTrap opens an in-memory artifact buffer. Safe to call even
// when the trap is disabled (returns a no-op handle).
func newCaptchaTrap(label string) *captchaTrap {
	return &captchaTrap{
		label:   label,
		started: time.Now(),
		files:   map[string][]byte{},
	}
}

// Save records an artifact (a file that will be written to disk if the
// trap commits). The data is copied so callers can reuse the slice.
func (t *captchaTrap) Save(name string, data []byte) {
	if t == nil || captchaTrapRoot() == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flushed {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	t.files[sanitizeArtifactName(name)] = cp
}

// Note appends a human-readable line that lands in notes.log on commit.
func (t *captchaTrap) Note(format string, args ...any) {
	if t == nil || captchaTrapRoot() == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flushed {
		return
	}
	t.notes = append(t.notes, fmt.Sprintf("[%s] %s",
		time.Now().Format("15:04:05.000"),
		fmt.Sprintf(format, args...)))
}

// Commit flushes the buffer to disk under a fresh subdirectory. Safe to
// call multiple times; only the first call writes.
func (t *captchaTrap) Commit(reason string) {
	if t == nil {
		return
	}
	root := captchaTrapRoot()
	if root == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flushed {
		return
	}
	t.flushed = true

	subdir := filepath.Join(root, fmt.Sprintf("%s_%s_%s",
		t.started.Format("20060102_150405"),
		t.label,
		shortRandHex(3)))
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		log.Printf("captcha-trap: commit mkdir %q failed: %v", subdir, err)
		return
	}

	for name, data := range t.files {
		if err := os.WriteFile(filepath.Join(subdir, name), data, 0o644); err != nil {
			log.Printf("captcha-trap: write %s/%s failed: %v", subdir, name, err)
		}
	}

	notesBlob := strings.Builder{}
	fmt.Fprintf(&notesBlob, "label:    %s\n", t.label)
	fmt.Fprintf(&notesBlob, "reason:   %s\n", reason)
	fmt.Fprintf(&notesBlob, "started:  %s\n", t.started.Format(time.RFC3339Nano))
	fmt.Fprintf(&notesBlob, "duration: %s\n", time.Since(t.started))
	notesBlob.WriteString("---\n")
	for _, n := range t.notes {
		notesBlob.WriteString(n)
		notesBlob.WriteByte('\n')
	}
	_ = os.WriteFile(filepath.Join(subdir, "notes.log"), []byte(notesBlob.String()), 0o644)

	log.Printf("captcha-trap: saved %d artefacts to %s (reason=%s)",
		len(t.files), subdir, reason)
}

// Discard drops the in-memory buffer without touching disk. The deferred
// safety net for the happy path: if the solve returns a success token,
// Discard frees the buffer and nothing is persisted.
func (t *captchaTrap) Discard() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flushed {
		return
	}
	t.flushed = true
	t.files = nil
	t.notes = nil
}

func sanitizeArtifactName(name string) string {
	// Keep filenames flat and predictable — anything iOS' file browsers
	// can choke on (slashes, leading dots) gets normalised away.
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == '\\' || r == 0:
			return '_'
		default:
			return r
		}
	}, name)
	cleaned = strings.TrimLeft(cleaned, ".")
	if cleaned == "" {
		cleaned = "artifact"
	}
	return cleaned
}

func shortRandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "noid"
	}
	return hex.EncodeToString(b)
}
