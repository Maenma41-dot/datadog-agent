// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package eventbuf

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Reassembly tuning.
const (
	// FragmentTimeout is how long the reassembly store holds an incomplete
	// fragment set before evicting it. All fragments from a single probe
	// invocation are produced in microseconds; this timeout is very generous.
	FragmentTimeout = 100 * time.Millisecond
	// MaxPendingFragmentSets caps the number of in-flight reassembly sets to
	// bound memory usage.
	MaxPendingFragmentSets = 64
)

// FragmentKey identifies one in-flight fragment series. The ktime of the
// first fragment disambiguates otherwise identical (goid, depth, probeID)
// triples when a function is re-invoked rapidly.
type FragmentKey struct {
	Goid           uint64
	StackByteDepth uint32
	ProbeID        uint32
	KtimeNs        uint64
}

type pendingReassembly struct {
	list     *MessageList
	lastSeq  uint16
	deadline time.Time
}

// ReassemblyStore accumulates continuation fragments for in-flight events
// until each series is complete, then surfaces the full list.
type ReassemblyStore struct {
	pending map[FragmentKey]*pendingReassembly
	now     func() time.Time // injectable clock (defaults to time.Now)
}

// NewReassemblyStore returns a fresh store.
func NewReassemblyStore() *ReassemblyStore {
	return &ReassemblyStore{
		pending: make(map[FragmentKey]*pendingReassembly),
		now:     time.Now,
	}
}

// AddFragment records a fragment belonging to the invocation identified by
// key. seq is the fragment's continuation_seq; isFinal is true when no
// further fragments are expected (HasMoreFragments == false).
//
// Return value:
//   - (list, true) if this fragment completed the series; caller owns list.
//   - (nil,  false) if more fragments are expected; msg is retained.
//   - (nil,  true) if this fragment is an orphan continuation (seq > 0 with
//     no preceding first fragment); msg has been released.
//
// When seq == 0 (first fragment), AddFragment runs an eviction pass over
// expired entries to bound memory usage.
func (rs *ReassemblyStore) AddFragment(
	key FragmentKey, msg Message, seq uint16, isFinal bool,
) (*MessageList, bool) {
	if seq == 0 {
		rs.evictExpired()
		pe := &pendingReassembly{
			list:     NewMessageList(msg),
			deadline: rs.now().Add(FragmentTimeout),
		}
		rs.pending[key] = pe
		if isFinal {
			// seq=0 with no more fragments: caller asserts this is a
			// continuation, so surface it as a complete single-fragment
			// series. (This should not happen in practice, but we tolerate
			// it rather than leaking.)
			delete(rs.pending, key)
			return pe.list, true
		}
		return nil, false
	}

	pe, ok := rs.pending[key]
	if !ok {
		// First fragment was dropped. Discard this continuation.
		log.Tracef(
			"orphan continuation fragment seq=%d for goid=%d probe=%d",
			seq, key.Goid, key.ProbeID,
		)
		msg.Release()
		return nil, true
	}

	pe.list.Append(msg)
	pe.lastSeq = seq
	if !isFinal {
		return nil, false
	}
	delete(rs.pending, key)
	return pe.list, true
}

// Close releases every pending fragment series and empties the store.
func (rs *ReassemblyStore) Close() {
	for key, pe := range rs.pending {
		pe.list.Release()
		delete(rs.pending, key)
	}
}

// evictExpired releases any pending fragment series past its deadline, and
// trims the pending set to MaxPendingFragmentSets by evicting the oldest
// entries (by deadline).
func (rs *ReassemblyStore) evictExpired() {
	if len(rs.pending) == 0 {
		return
	}
	now := rs.now()
	for key, pe := range rs.pending {
		if now.After(pe.deadline) {
			log.Tracef(
				"evicting expired fragment set for goid=%d probe=%d (seq=%d)",
				key.Goid, key.ProbeID, pe.lastSeq,
			)
			pe.list.Release()
			delete(rs.pending, key)
		}
	}
	for len(rs.pending) >= MaxPendingFragmentSets {
		var oldestKey FragmentKey
		var oldestDeadline time.Time
		for key, pe := range rs.pending {
			if oldestDeadline.IsZero() || pe.deadline.Before(oldestDeadline) {
				oldestKey = key
				oldestDeadline = pe.deadline
			}
		}
		if pe, ok := rs.pending[oldestKey]; ok {
			pe.list.Release()
		}
		delete(rs.pending, oldestKey)
	}
}
