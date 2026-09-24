package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform"
	"google.golang.org/protobuf/proto"
)

// useGeoAssets points Xray's asset resolution at a generated geoip.dat so tests
// that build a freedom outbound stay hermetic. Routes built with
// allowPrivateOutbound=true inject a "geoip:private" final rule, and Xray opens
// geoip.dat while resolving that attribute, so the file must exist even though
// these tests never start a core. Only the code has to be present for that
// resolution to succeed; the CIDR list is read lazily, long after Build().
func useGeoAssets(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	body, err := proto.Marshal(&geodata.GeoIP{Code: "PRIVATE"})
	if err != nil {
		t.Fatalf("marshal geoip entry: %v", err)
	}

	// Xray reads the dat as a sequence of [tag byte][varint body length][body]
	// records, so frame the marshalled GeoIP the same way the real file is.
	var buf bytes.Buffer
	buf.WriteByte(0x0A)
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], uint64(len(body)))
	buf.Write(length[:n])
	buf.Write(body)

	if err := os.WriteFile(filepath.Join(dir, geoIPAsset), buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", geoIPAsset, err)
	}
	t.Setenv(platform.AssetLocation, dir)
}

func TestCheckGeoIPAssetAtMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), geoIPAsset)

	err := checkGeoIPAssetAt(path)
	if err == nil {
		t.Fatal("expected error for a missing geoip.dat")
	}
	msg := err.Error()
	for _, want := range []string{geoIPAsset, path, "--asset-dir"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
}

func TestCheckGeoIPAssetAtRejectsNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), geoIPAsset)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err := checkGeoIPAssetAt(path)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected not-a-regular-file error, got %v", err)
	}
}

func TestCheckGeoIPAssetAtAcceptsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), geoIPAsset)
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := checkGeoIPAssetAt(path); err != nil {
		t.Fatalf("checkGeoIPAssetAt returned error: %v", err)
	}
}

// TestCheckGeoIPAssetUsesAssetDir confirms the preflight resolves the path the
// same way Xray does, i.e. through xray.location.asset set by --asset-dir.
func TestCheckGeoIPAssetUsesAssetDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(platform.AssetLocation, dir)
	if err := os.WriteFile(filepath.Join(dir, geoIPAsset), []byte("stub"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := checkGeoIPAsset(); err != nil {
		t.Fatalf("checkGeoIPAsset returned error: %v", err)
	}
}

func TestAnnotateGeoAssetError(t *testing.T) {
	sentinel := errors.New("boom")
	tests := []struct {
		name     string
		err      error
		wantHint string
		wantSame bool
	}{
		{name: "nil", err: nil, wantSame: true},
		{name: "unrelated", err: sentinel, wantSame: true},
		{
			name:     "missing geosite",
			err:      errors.New("illegal domain rule: geosite:netflix > failed to open geosite.dat > stat /etc/xray/geosite.dat: no such file or directory"),
			wantHint: "--asset-dir",
		},
		{
			name:     "missing geoip",
			err:      errors.New("illegal ip rule: geoip:cn > failed to open geoip.dat > stat geoip.dat: no such file or directory"),
			wantHint: "--asset-dir",
		},
		{
			name:     "unknown code",
			err:      errors.New("illegal ip rule: geoip:cn > failed to check code CN from geoip.dat > EOF"),
			wantHint: "not present in geoip.dat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := annotateGeoAssetError(tt.err)
			if tt.wantSame {
				if !errors.Is(got, tt.err) {
					t.Fatalf("annotateGeoAssetError(%v) = %v, want the original error", tt.err, got)
				}
				return
			}
			if !strings.Contains(got.Error(), "hint:") || !strings.Contains(got.Error(), tt.wantHint) {
				t.Fatalf("annotated error = %q, want a hint mentioning %q", got, tt.wantHint)
			}
			if !errors.Is(got, tt.err) {
				t.Fatalf("annotated error lost the original cause: %v", got)
			}
		})
	}
}
