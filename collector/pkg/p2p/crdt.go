package p2p

import (
	"sync"
	"time"
)

// CRDTBanEntry represents an addition to the replicated quarantine set.
type CRDTBanEntry struct {
	TargetIP         string `json:"target_ip"`
	Subnet           string `json:"subnet"`
	AttackerASN      string `json:"attacker_asn"`
	CountryCode      string `json:"country_code"`
	FlagEmoji        string `json:"flag_emoji"`
	ThreatScore      int    `json:"threat_score"`
	OriginNodeID     string `json:"origin_node_id"`
	TimestampMs      int64  `json:"timestamp_ms"`
	TTLSeconds       int64  `json:"ttl_seconds"`
	ExpireTimeMs     int64  `json:"expire_time_ms"`
	MitigationReason string `json:"mitigation_reason"`
	Preemptive       bool   `json:"preemptive"`
}

// CRDTRemoveEntry represents a deletion/unban in the observed-remove set.
type CRDTRemoveEntry struct {
	TargetIP     string `json:"target_ip"`
	TimestampMs  int64  `json:"timestamp_ms"`
	OriginNodeID string `json:"origin_node_id"`
	Reason       string `json:"reason"`
}

// CRDTSwarmJail implements a Conflict-Free Replicated Data Type (LWW-Element-Set)
// for decentralized, partition-tolerant quarantine synchronization across the fleet.
type CRDTSwarmJail struct {
	mu        sync.RWMutex
	nodeID    string
	addSet    map[string]CRDTBanEntry
	removeSet map[string]CRDTRemoveEntry
	onBanHook func(entry CRDTBanEntry)
}

// NewCRDTSwarmJail creates a new CRDT jail instance.
func NewCRDTSwarmJail(nodeID string, onBanHook func(entry CRDTBanEntry)) *CRDTSwarmJail {
	return &CRDTSwarmJail{
		nodeID:    nodeID,
		addSet:    make(map[string]CRDTBanEntry),
		removeSet: make(map[string]CRDTRemoveEntry),
		onBanHook: onBanHook,
	}
}

// Add inserts or updates a ban in the replicated set.
func (j *CRDTSwarmJail) Add(entry CRDTBanEntry) bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now().UnixMilli()
	if entry.TimestampMs == 0 {
		entry.TimestampMs = now
	}
	if entry.ExpireTimeMs == 0 && entry.TTLSeconds > 0 {
		entry.ExpireTimeMs = entry.TimestampMs + (entry.TTLSeconds * 1000)
	}

	existingAdd, hasAdd := j.addSet[entry.TargetIP]
	existingRem, hasRem := j.removeSet[entry.TargetIP]

	// LWW Rule: If an unban occurred after this add timestamp, discard addition
	if hasRem && existingRem.TimestampMs >= entry.TimestampMs {
		return false
	}

	// If already in AddSet with equal or newer timestamp, ignore
	if hasAdd && existingAdd.TimestampMs >= entry.TimestampMs {
		return false
	}

	j.addSet[entry.TargetIP] = entry

	if j.onBanHook != nil {
		go j.onBanHook(entry)
	}
	return true
}

// Remove marks an IP as unbanned in the Remove-Set.
func (j *CRDTSwarmJail) Remove(ip string, reason string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now().UnixMilli()
	existingRem, hasRem := j.removeSet[ip]
	if hasRem && existingRem.TimestampMs >= now {
		return false
	}

	j.removeSet[ip] = CRDTRemoveEntry{
		TargetIP:     ip,
		TimestampMs:  now,
		OriginNodeID: j.nodeID,
		Reason:       reason,
	}
	return true
}

// Merge reconciles two CRDT sets atomically without central coordination.
func (j *CRDTSwarmJail) Merge(remoteAdd map[string]CRDTBanEntry, remoteRem map[string]CRDTRemoveEntry) []CRDTBanEntry {
	j.mu.Lock()
	defer j.mu.Unlock()

	var newlyEnforced []CRDTBanEntry

	// 1. Merge RemoveSet (LWW)
	for ip, rem := range remoteRem {
		existing, ok := j.removeSet[ip]
		if !ok || rem.TimestampMs > existing.TimestampMs {
			j.removeSet[ip] = rem
		}
	}

	// 2. Merge AddSet (LWW)
	now := time.Now().UnixMilli()
	for ip, add := range remoteAdd {
		// Check against RemoveSet
		if rem, ok := j.removeSet[ip]; ok && rem.TimestampMs >= add.TimestampMs {
			continue
		}

		// Check if expired
		if add.ExpireTimeMs > 0 && add.ExpireTimeMs <= now {
			continue
		}

		existing, ok := j.addSet[ip]
		if !ok || add.TimestampMs > existing.TimestampMs {
			j.addSet[ip] = add
			newlyEnforced = append(newlyEnforced, add)
			if j.onBanHook != nil {
				go j.onBanHook(add)
			}
		}
	}

	return newlyEnforced
}

// GetActiveBans returns all active, unexpired, non-removed quarantined entities.
func (j *CRDTSwarmJail) GetActiveBans() []CRDTBanEntry {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now().UnixMilli()
	var active []CRDTBanEntry

	for ip, add := range j.addSet {
		if rem, ok := j.removeSet[ip]; ok && rem.TimestampMs >= add.TimestampMs {
			continue
		}
		if add.ExpireTimeMs > 0 && add.ExpireTimeMs <= now {
			continue
		}
		active = append(active, add)
	}

	return active
}

// ExportState dumps the raw sets for gossip delta exchange.
func (j *CRDTSwarmJail) ExportState() (map[string]CRDTBanEntry, map[string]CRDTRemoveEntry) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	addCopy := make(map[string]CRDTBanEntry, len(j.addSet))
	for k, v := range j.addSet {
		addCopy[k] = v
	}

	remCopy := make(map[string]CRDTRemoveEntry, len(j.removeSet))
	for k, v := range j.removeSet {
		remCopy[k] = v
	}

	return addCopy, remCopy
}

// Count returns the active count in the CRDT set.
func (j *CRDTSwarmJail) Count() int {
	return len(j.GetActiveBans())
}
