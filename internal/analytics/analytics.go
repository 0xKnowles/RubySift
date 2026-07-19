// Package analytics turns decoded telemetry records into the aggregate
// views the dashboard renders: the 24-hour RF density heatmap and the
// signal-proximity clusters grouped by MAC address.
package analytics

import (
	"sort"

	"github.com/0xKnowles/RubySift/internal/parser"
)

// PulseBucket is one hour-of-day cell in the activity heatmap.
type PulseBucket struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

// PulseGrid buckets every wifi/ble/node record by hour-of-day (0-23),
// giving a GitHub-contribution-style view of ambient RF density.
func PulseGrid(records []parser.Record) []PulseBucket {
	buckets := make([]int, 24)
	for _, r := range records {
		if r.Type == parser.RecordCompanionState {
			continue
		}
		hour := int((r.Timestamp / 3600) % 24)
		buckets[hour]++
	}
	out := make([]PulseBucket, 24)
	for h, c := range buckets {
		out[h] = PulseBucket{Hour: h, Count: c}
	}
	return out
}

// ProximityCluster summarizes every unique MAC address seen, so the UI can
// separate distant background noise from devices that passed close by.
type ProximityCluster struct {
	MAC       string  `json:"mac"`
	Type      string  `json:"type"`
	Sightings int     `json:"sightings"`
	AvgRSSI   float64 `json:"avg_rssi"`
	MaxRSSI   int     `json:"max_rssi"`
	FirstSeen uint32  `json:"first_seen"`
	LastSeen  uint32  `json:"last_seen"`
}

// ProximityClusters groups records by MAC and computes signal statistics,
// sorted by strongest average RSSI (closest) first.
func ProximityClusters(records []parser.Record) []ProximityCluster {
	type acc struct {
		typeName    string
		count       int
		rssiSum     int
		maxRSSI     int
		first, last uint32
	}
	byMAC := make(map[string]*acc)
	for _, r := range records {
		if r.Type == parser.RecordCompanionState {
			continue
		}
		a, ok := byMAC[r.MAC]
		if !ok {
			a = &acc{typeName: r.TypeName, maxRSSI: int(r.RSSI), first: r.Timestamp, last: r.Timestamp}
			byMAC[r.MAC] = a
		}
		a.count++
		a.rssiSum += int(r.RSSI)
		if int(r.RSSI) > a.maxRSSI {
			a.maxRSSI = int(r.RSSI)
		}
		if r.Timestamp < a.first {
			a.first = r.Timestamp
		}
		if r.Timestamp > a.last {
			a.last = r.Timestamp
		}
	}
	out := make([]ProximityCluster, 0, len(byMAC))
	for mac, a := range byMAC {
		out = append(out, ProximityCluster{
			MAC:       mac,
			Type:      a.typeName,
			Sightings: a.count,
			AvgRSSI:   float64(a.rssiSum) / float64(a.count),
			MaxRSSI:   a.maxRSSI,
			FirstSeen: a.first,
			LastSeen:  a.last,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AvgRSSI > out[j].AvgRSSI })
	return out
}
