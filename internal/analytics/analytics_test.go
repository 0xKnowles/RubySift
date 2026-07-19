package analytics

import (
	"testing"

	"github.com/0xKnowles/RubySift/internal/parser"
)

func rec(hour int, typ parser.RecordType, mac string, rssi int8, label string) parser.Record {
	return parser.Record{
		Timestamp: uint32(hour * 3600),
		Type:      typ,
		TypeName:  typ.String(),
		MAC:       mac,
		RSSI:      rssi,
		Label:     label,
	}
}

func TestPulseGridBucketsByHour(t *testing.T) {
	records := []parser.Record{
		rec(3, parser.RecordWiFiHandshake, "aa:aa:aa:aa:aa:aa", -50, ""),
		rec(3, parser.RecordBLEDevice, "bb:bb:bb:bb:bb:bb", -60, ""),
		rec(9, parser.RecordWiFiHandshake, "cc:cc:cc:cc:cc:cc", -70, ""),
	}
	grid := PulseGrid(records)
	if len(grid) != 24 {
		t.Fatalf("expected 24 buckets, got %d", len(grid))
	}
	if grid[3].Count != 2 {
		t.Errorf("hour 3 count = %d, want 2", grid[3].Count)
	}
	if grid[9].Count != 1 {
		t.Errorf("hour 9 count = %d, want 1", grid[9].Count)
	}
}

func TestProximityClustersAggregatesByMAC(t *testing.T) {
	records := []parser.Record{
		rec(1, parser.RecordWiFiHandshake, "aa:aa:aa:aa:aa:aa", -40, "HomeWiFi"),
		rec(2, parser.RecordWiFiHandshake, "aa:aa:aa:aa:aa:aa", -60, "HomeWiFi"),
		rec(1, parser.RecordBLEDevice, "bb:bb:bb:bb:bb:bb", -90, "Earbuds"),
	}
	clusters := ProximityClusters(records)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}
	// Sorted strongest (closest) average RSSI first.
	if clusters[0].MAC != "aa:aa:aa:aa:aa:aa" {
		t.Errorf("expected aa:.. cluster first, got %s", clusters[0].MAC)
	}
	if clusters[0].Sightings != 2 {
		t.Errorf("sightings = %d, want 2", clusters[0].Sightings)
	}
	if clusters[0].AvgRSSI != -50 {
		t.Errorf("avg rssi = %v, want -50", clusters[0].AvgRSSI)
	}
	if clusters[0].MaxRSSI != -40 {
		t.Errorf("max rssi = %d, want -40", clusters[0].MaxRSSI)
	}
	if clusters[0].Label != "HomeWiFi" {
		t.Errorf("label = %q, want HomeWiFi", clusters[0].Label)
	}
}
