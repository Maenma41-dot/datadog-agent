// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package eventbuf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReassemblyStoreSingleFragmentSeriesCompletes(t *testing.T) {
	rs := NewReassemblyStore()

	key := FragmentKey{Goid: 1, ProbeID: 1, KtimeNs: 1000}

	// Fragment 0, not final.
	m0 := newTestMessage(100)
	list, done := rs.AddFragment(key, m0, 0, false /*isFinal*/)
	require.False(t, done)
	require.Nil(t, list)

	// Fragment 1, final.
	m1 := newTestMessage(80)
	list, done = rs.AddFragment(key, m1, 1, true /*isFinal*/)
	require.True(t, done)
	require.NotNil(t, list)
	assert.Equal(t, 180, list.TotalSize())

	// No stale entries.
	assert.Empty(t, rs.pending)
	list.Release()
}

func TestReassemblyStoreOrphanContinuation(t *testing.T) {
	rs := NewReassemblyStore()

	key := FragmentKey{Goid: 1, ProbeID: 1, KtimeNs: 1000}

	// Continuation with no preceding seq=0 → orphan.
	m := newTestMessage(80)
	list, done := rs.AddFragment(key, m, 3, false /*isFinal*/)
	require.True(t, done, "orphan should be immediately done")
	require.Nil(t, list)
	assert.True(t, m.released, "orphan message should be released")
}

func TestReassemblyStoreFirstFragmentIsAlsoFinal(t *testing.T) {
	// seq=0 with !HasMoreFragments arrives: caller treats it as complete.
	rs := NewReassemblyStore()

	key := FragmentKey{Goid: 1, ProbeID: 1, KtimeNs: 1000}

	m0 := newTestMessage(100)
	list, done := rs.AddFragment(key, m0, 0, true /*isFinal*/)
	require.True(t, done)
	require.NotNil(t, list)
	assert.Equal(t, 100, list.TotalSize())
	assert.Empty(t, rs.pending)
	list.Release()
}

func TestReassemblyStoreEvictExpired(t *testing.T) {
	rs := NewReassemblyStore()

	// Fake clock: returns whatever now is currently set to.
	var now time.Time
	rs.now = func() time.Time { return now }

	// t = baseline.
	now = time.Unix(1000, 0)

	expiredKey := FragmentKey{Goid: 1, ProbeID: 1, KtimeNs: 1000}
	_, _ = rs.AddFragment(expiredKey, newTestMessage(32), 0, false)

	// Advance clock past the fragment timeout.
	now = now.Add(FragmentTimeout + time.Second)

	// Add a fresh fragment series; this triggers eviction of the expired one.
	freshKey := FragmentKey{Goid: 2, ProbeID: 2, KtimeNs: 2000}
	_, _ = rs.AddFragment(freshKey, newTestMessage(32), 0, false)

	_, expiredStillPresent := rs.pending[expiredKey]
	assert.False(t, expiredStillPresent, "expired series should be evicted")
	_, freshPresent := rs.pending[freshKey]
	assert.True(t, freshPresent)
}

func TestReassemblyStoreFIFOEvictionAtCap(t *testing.T) {
	rs := NewReassemblyStore()

	// Add MaxPendingFragmentSets+1 first-fragments without them expiring.
	var now time.Time = time.Unix(1000, 0)
	rs.now = func() time.Time { return now }

	keys := make([]FragmentKey, 0, MaxPendingFragmentSets+1)
	for i := 0; i < MaxPendingFragmentSets+1; i++ {
		key := FragmentKey{Goid: uint64(i + 1), ProbeID: 1, KtimeNs: uint64(1000 + i)}
		keys = append(keys, key)
		// Advance wall clock slightly so deadlines are ordered.
		now = now.Add(time.Microsecond)
		_, _ = rs.AddFragment(key, newTestMessage(32), 0, false)
	}

	// The oldest key should have been evicted.
	_, firstStillPresent := rs.pending[keys[0]]
	assert.False(t, firstStillPresent, "oldest should be evicted at cap")
	assert.Equal(t, MaxPendingFragmentSets, len(rs.pending))
}

func TestReassemblyStoreClose(t *testing.T) {
	rs := NewReassemblyStore()

	var msgs []*testMessage
	for i := 0; i < 5; i++ {
		m := newTestMessage(32)
		msgs = append(msgs, m)
		key := FragmentKey{Goid: uint64(i + 1), ProbeID: 1, KtimeNs: uint64(i + 1000)}
		_, _ = rs.AddFragment(key, m, 0, false)
	}

	rs.Close()
	assert.Empty(t, rs.pending)
	for i, m := range msgs {
		assert.Truef(t, m.released, "message %d should be released", i)
	}
}
