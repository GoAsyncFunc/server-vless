package service

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform"
	"google.golang.org/protobuf/proto"
)

// useGeoAssets points Xray's asset resolution at a generated geoip.dat so that
// config-building tests stay hermetic and do not need the released dat files.
//
// The direct egress now gates private destinations with Xray's "geoip:private"
// attribute, and Xray resolves that attribute at config-build time by scanning
// geoip.dat for the code, so building the outbound config requires the file to
// be present. Tests only care that resolution succeeds, not which ranges the
// attribute contains; the real dat files are exercised end to end instead.
func useGeoAssets(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	writeGeoIPDat(t, filepath.Join(dir, "geoip.dat"))
	t.Setenv(platform.AssetLocation, dir)
}

func writeGeoIPDat(t *testing.T, path string) {
	t.Helper()
	entry := &geodata.GeoIP{
		Code: "PRIVATE",
		Cidr: []*geodata.CIDR{
			{Ip: net.IPv4(10, 0, 0, 0).To4(), Prefix: 8},
			{Ip: net.IPv4(127, 0, 0, 0).To4(), Prefix: 8},
		},
	}
	body, err := proto.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal geoip entry: %v", err)
	}

	// Xray walks the dat as a sequence of records shaped
	// [tag byte][varint body length][body], where body is a marshalled GeoIP
	// whose first field is the code. Matching relies on the code being that
	// first field, so keep the entry's field order intact.
	var buf bytes.Buffer
	buf.WriteByte(0x0A)
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], uint64(len(body)))
	buf.Write(length[:n])
	buf.Write(body)

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertPrivateIPRule checks that a freedom final rule carries the
// geoip:private attribute rather than a hand-maintained CIDR list.
func assertPrivateIPRule(t *testing.T, ip []*geodata.IPRule) {
	t.Helper()
	if len(ip) != 1 {
		t.Fatalf("rule IP count = %d, want 1 (%s)", len(ip), privateIPRule)
	}
	geo := ip[0].GetGeoip()
	if geo == nil || geo.GetFile() != "geoip.dat" || geo.GetCode() != "PRIVATE" {
		t.Fatalf("rule IP = %v, want %s", ip, privateIPRule)
	}
}
