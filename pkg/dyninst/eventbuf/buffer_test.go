// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package eventbuf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// k builds a Key used across tests.
func k(goid uint64, entryKtime uint64) Key {
	return Key{Goid: goid, StackByteDepth: 100, ProbeID: 1, EntryKtime: entryKtime}
}

// ------------------------------------------------------------------
// Basic pairing (no drops).
// ------------------------------------------------------------------

// 1. Entry + return, both single-fragment.
func TestBuffer_EntryReturnSingleFragment(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)
	rm := newTestMessage(4)

	r, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done, "entry alone is not final for paired probe")
	require.Nil(t, r.Entry)

	r, done = b.AddFragment(k(1, 1000), rm, Return, 0, true, false)
	require.True(t, done)
	require.NotNil(t, r.Entry)
	require.NotNil(t, r.Return)
	assert.False(t, r.EntryTruncated)
	assert.False(t, r.ReturnTruncated)
	assert.False(t, r.ReturnLost)
	r.Entry.Release()
	r.Return.Release()
	assert.True(t, em.released)
	assert.True(t, rm.released)
	assert.Equal(t, 0, b.Len())
}

// 2. Entry multi-fragment + return single.
func TestBuffer_EntryMultiReturnSingle(t *testing.T) {
	b := newTestBuffer()
	e0 := newTestMessage(8)
	e1 := newTestMessage(8)
	rm := newTestMessage(4)

	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, true)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), e1, Entry, 1, true, true)
	require.False(t, done, "entry assembled but return not yet here")

	r, done := b.AddFragment(k(1, 1000), rm, Return, 0, true, false)
	require.True(t, done)
	// Ready.Entry should have two messages.
	count := 0
	for range r.Entry.Fragments() {
		count++
	}
	assert.Equal(t, 2, count)
	r.Entry.Release()
	r.Return.Release()
}

// 3. Entry single + return multi-fragment.
func TestBuffer_EntrySingleReturnMulti(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)
	r0 := newTestMessage(4)
	r1 := newTestMessage(4)

	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), r0, Return, 0, false, false)
	require.False(t, done)
	r, done := b.AddFragment(k(1, 1000), r1, Return, 1, true, false)
	require.True(t, done)
	count := 0
	for range r.Return.Fragments() {
		count++
	}
	assert.Equal(t, 2, count)
	r.Entry.Release()
	r.Return.Release()
}

// 4. Both multi-fragment.
func TestBuffer_EntryReturnBothMulti(t *testing.T) {
	b := newTestBuffer()
	e0, e1 := newTestMessage(8), newTestMessage(8)
	r0, r1 := newTestMessage(4), newTestMessage(4)

	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, true)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), e1, Entry, 1, true, true)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), r0, Return, 0, false, false)
	require.False(t, done)
	r, done := b.AddFragment(k(1, 1000), r1, Return, 1, true, false)
	require.True(t, done)
	r.Entry.Release()
	r.Return.Release()
}

// 5. Standalone (no return) single fragment.
func TestBuffer_StandaloneSingle(t *testing.T) {
	b := newTestBuffer()
	m := newTestMessage(16)
	r, done := b.AddFragment(k(1, 1000), m, Entry, 0, true, false /*expectReturn*/)
	require.True(t, done)
	require.NotNil(t, r.Entry)
	assert.Nil(t, r.Return)
	r.Entry.Release()
}

// 6. Standalone multi-fragment.
func TestBuffer_StandaloneMulti(t *testing.T) {
	b := newTestBuffer()
	m0, m1 := newTestMessage(16), newTestMessage(16)
	_, done := b.AddFragment(k(1, 1000), m0, Entry, 0, false, false)
	require.False(t, done)
	r, done := b.AddFragment(k(1, 1000), m1, Entry, 1, true, false)
	require.True(t, done)
	r.Entry.Release()
}

// ------------------------------------------------------------------
// RETURN_LOST.
// ------------------------------------------------------------------

// 7. Entry complete; RETURN_LOST → emit entry alone.
func TestBuffer_ReturnLost_EntryComplete(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)

	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)

	r, done := b.NoteReturnLost(k(1, 1000))
	require.True(t, done)
	assert.NotNil(t, r.Entry)
	assert.Nil(t, r.Return)
	assert.True(t, r.ReturnLost)
	assert.False(t, r.EntryTruncated)
	r.Entry.Release()
}

// 9. RETURN_LOST arrives before entry; entry arrives later; finalize.
func TestBuffer_ReturnLost_BeforeEntry(t *testing.T) {
	b := newTestBuffer()
	_, done := b.NoteReturnLost(k(1, 1000))
	require.False(t, done, "no entry yet, can't finalize")

	em := newTestMessage(8)
	r, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.True(t, done)
	assert.True(t, r.ReturnLost)
	r.Entry.Release()
}

// ------------------------------------------------------------------
// PARTIAL_ENTRY.
// ------------------------------------------------------------------

// 10. Fragment 0 (not marked final) + PARTIAL_ENTRY(last_seq=0) → emit truncated.
// This represents: fragment 0 was sent with HasMoreFragments=true, then BPF
// discovered it couldn't send more, so sent PARTIAL_ENTRY(last_seq=0).
func TestBuffer_PartialEntry_ImmediateAfterFragments(t *testing.T) {
	b := newTestBuffer()
	e0 := newTestMessage(8)

	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, false)
	require.False(t, done)

	r, done := b.NotePartial(k(1, 1000), Entry, 0)
	require.True(t, done)
	assert.True(t, r.EntryTruncated)
	assert.False(t, r.ReturnTruncated)
	assert.Nil(t, r.Return)
	r.Entry.Release()
}

// 11. Fragments 0, 1 + PARTIAL_ENTRY(last_seq=1); then return arrives → paired, entry truncated.
func TestBuffer_PartialEntry_ThenReturn(t *testing.T) {
	b := newTestBuffer()
	e0, e1 := newTestMessage(8), newTestMessage(8)

	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, true)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), e1, Entry, 1, false /*!isFinal*/, true)
	require.False(t, done)

	_, done = b.NotePartial(k(1, 1000), Entry, 1) // last_seq=1 -> expect 2 fragments
	require.False(t, done, "entry assembled as truncated but return still expected")

	rm := newTestMessage(4)
	r, done := b.AddFragment(k(1, 1000), rm, Return, 0, true, false)
	require.True(t, done)
	assert.True(t, r.EntryTruncated)
	assert.False(t, r.ReturnTruncated)
	r.Entry.Release()
	r.Return.Release()
}

// 12. PARTIAL_ENTRY arrives before any fragments; fragments arrive later; finalize.
func TestBuffer_PartialEntry_BeforeFragments(t *testing.T) {
	b := newTestBuffer()
	_, done := b.NotePartial(k(1, 1000), Entry, 1)
	require.False(t, done)

	e0 := newTestMessage(8)
	_, done = b.AddFragment(k(1, 1000), e0, Entry, 0, false, false)
	require.False(t, done, "expected 2 fragments, only have 1")

	e1 := newTestMessage(8)
	r, done := b.AddFragment(k(1, 1000), e1, Entry, 1, false, false)
	require.True(t, done, "2 fragments received, matches expected")
	assert.True(t, r.EntryTruncated)
	r.Entry.Release()
}

// 13. PARTIAL_ENTRY after fragments 0, 1 already present (both non-final) →
//     expected = last_seq+1 = 2, so immediate finalize.
func TestBuffer_PartialEntry_AfterFragmentsAlreadyPresent(t *testing.T) {
	b := newTestBuffer()
	e0, e1 := newTestMessage(8), newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, false)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), e1, Entry, 1, false, false)
	require.False(t, done)

	r, done := b.NotePartial(k(1, 1000), Entry, 1)
	require.True(t, done)
	assert.True(t, r.EntryTruncated)
	r.Entry.Release()
}

// 14. PARTIAL_ENTRY(last_seq=2) with only fragments 0, 1 present → wait for seq 2.
func TestBuffer_PartialEntry_WaitForMoreFragments(t *testing.T) {
	b := newTestBuffer()
	e0, e1 := newTestMessage(8), newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), e0, Entry, 0, false, false)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), e1, Entry, 1, false, false)
	require.False(t, done)

	_, done = b.NotePartial(k(1, 1000), Entry, 2)
	require.False(t, done, "only 2 of 3 fragments received")

	e2 := newTestMessage(8)
	r, done := b.AddFragment(k(1, 1000), e2, Entry, 2, false, false)
	require.True(t, done)
	assert.True(t, r.EntryTruncated)
	r.Entry.Release()
}

// ------------------------------------------------------------------
// PARTIAL_RETURN.
// ------------------------------------------------------------------

// 15. Entry complete + return fragments + PARTIAL_RETURN → emit paired, truncated.
func TestBuffer_PartialReturn_AfterFragments(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)
	r0, r1 := newTestMessage(4), newTestMessage(4)
	_, done = b.AddFragment(k(1, 1000), r0, Return, 0, false, false)
	require.False(t, done)
	_, done = b.AddFragment(k(1, 1000), r1, Return, 1, false, false)
	require.False(t, done)

	r, done := b.NotePartial(k(1, 1000), Return, 1)
	require.True(t, done)
	assert.True(t, r.ReturnTruncated)
	assert.False(t, r.EntryTruncated)
	r.Entry.Release()
	r.Return.Release()
}

// 16. PARTIAL_RETURN before return fragments → fragments arrive → finalize.
func TestBuffer_PartialReturn_BeforeFragments(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)
	_, done = b.NotePartial(k(1, 1000), Return, 0)
	require.False(t, done)
	rm := newTestMessage(4)
	r, done := b.AddFragment(k(1, 1000), rm, Return, 0, false, false)
	require.True(t, done)
	assert.True(t, r.ReturnTruncated)
	r.Entry.Release()
	r.Return.Release()
}

// 17. PARTIAL_RETURN before entry; entry arrives; return arrives; finalize truncated.
func TestBuffer_PartialReturn_BeforeEntry(t *testing.T) {
	b := newTestBuffer()
	_, done := b.NotePartial(k(1, 1000), Return, 0)
	require.False(t, done)

	em := newTestMessage(8)
	_, done = b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)

	rm := newTestMessage(4)
	r, done := b.AddFragment(k(1, 1000), rm, Return, 0, false, false)
	require.True(t, done)
	assert.True(t, r.ReturnTruncated)
	r.Entry.Release()
	r.Return.Release()
}

// ------------------------------------------------------------------
// Rapid re-invocation.
// ------------------------------------------------------------------

// 18. Call N entry + RETURN_LOST(N) + call N+1 entry + normal N+1 return.
func TestBuffer_RapidReinvocation_DifferentEntryKtime(t *testing.T) {
	b := newTestBuffer()
	em1 := newTestMessage(8)
	em2 := newTestMessage(8)

	_, done := b.AddFragment(k(1, 1000), em1, Entry, 0, true, true)
	require.False(t, done)
	r1, done := b.NoteReturnLost(k(1, 1000))
	require.True(t, done, "RETURN_LOST on complete entry finalizes")
	assert.True(t, r1.ReturnLost)
	r1.Entry.Release()

	_, done = b.AddFragment(k(1, 2000), em2, Entry, 0, true, true)
	require.False(t, done)
	rm2 := newTestMessage(4)
	r2, done := b.AddFragment(k(1, 2000), rm2, Return, 0, true, false)
	require.True(t, done)
	assert.False(t, r2.ReturnLost)
	r2.Entry.Release()
	r2.Return.Release()
}

// 19. Interleaved N and N+1 fragments in the buffer simultaneously.
func TestBuffer_RapidReinvocation_SimultaneousInTree(t *testing.T) {
	b := newTestBuffer()
	e1a, e1b := newTestMessage(8), newTestMessage(8)
	e2a, e2b := newTestMessage(8), newTestMessage(8)

	// Call N (EntryKtime=1000): fragment 0.
	_, done := b.AddFragment(k(1, 1000), e1a, Entry, 0, false, false)
	require.False(t, done)
	// Call N+1 (EntryKtime=2000): fragment 0.
	_, done = b.AddFragment(k(1, 2000), e2a, Entry, 0, false, false)
	require.False(t, done)
	assert.Equal(t, 2, b.Len(), "two independent invocations in the tree")

	// Finish call N.
	r1, done := b.AddFragment(k(1, 1000), e1b, Entry, 1, true, false)
	require.True(t, done)
	r1.Entry.Release()

	// Call N+1 still present.
	assert.Equal(t, 1, b.Len())

	// Finish call N+1.
	r2, done := b.AddFragment(k(1, 2000), e2b, Entry, 1, true, false)
	require.True(t, done)
	r2.Entry.Release()
	assert.Equal(t, 0, b.Len())
}

// 20. Stale notification for N arrives after N has finalized; creates a
//     zombie entry; GC cleans up.
func TestBuffer_StaleNotification_GCedByEvictStale(t *testing.T) {
	b := newTestBuffer()
	// Complete call N.
	em := newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, false)
	require.True(t, done)

	// Stale NoteReturnLost for N: creates a new entry with no fragments.
	_, done = b.NoteReturnLost(k(1, 1000))
	require.False(t, done, "no fragments means can't finalize")
	assert.Equal(t, 1, b.Len(), "zombie entry persists")

	// Issue a bunch of mutations on other keys to move the touchCt forward.
	for i := uint64(100); i < 110; i++ {
		m := newTestMessage(8)
		_, _ = b.AddFragment(k(i, i*10), m, Entry, 0, true, false)
	}

	// Evict stale entries older than maxIdle=5.
	evicted := b.EvictStale(5)
	// The zombie should be evicted (it's at touch=1, touchCt is now 12).
	require.NotEmpty(t, evicted)
	found := false
	for _, r := range evicted {
		if r.Key == k(1, 1000) {
			found = true
			assert.True(t, r.ReturnLost)
			// No entry fragments, so Entry should be nil.
			assert.Nil(t, r.Entry)
		}
	}
	assert.True(t, found, "zombie entry should have been evicted")
}

// ------------------------------------------------------------------
// Edge cases.
// ------------------------------------------------------------------

// 21. Single-fragment event (HasMoreFragments=false, seq=0).
func TestBuffer_SingleFragmentStandalone(t *testing.T) {
	b := newTestBuffer()
	m := newTestMessage(8)
	r, done := b.AddFragment(k(1, 1000), m, Entry, 0, true, false)
	require.True(t, done)
	r.Entry.Release()
}

// 22. EvictStale: entries older than maxIdle are evicted.
func TestBuffer_EvictStale_Cutoff(t *testing.T) {
	b := newTestBuffer()
	// Oldest entry.
	m := newTestMessage(8)
	_, _ = b.AddFragment(k(1, 1000), m, Entry, 0, false, false)

	// A bunch of newer mutations.
	for i := uint64(2); i < 10; i++ {
		mm := newTestMessage(4)
		_, _ = b.AddFragment(k(i, i*1000), mm, Entry, 0, false, false)
	}

	// Evict entries not touched in the last 5 mutations.
	evicted := b.EvictStale(5)
	// The first entry is touched at touchCt=1, current is 9.
	// cutoff = 9 - 5 = 4 => evict entries with touch <= 4.
	// Entries 1, 2, 3, 4 should be evicted.
	keys := make(map[Key]bool)
	for _, r := range evicted {
		keys[r.Key] = true
		if r.Entry != nil {
			r.Entry.Release()
		}
	}
	assert.True(t, keys[k(1, 1000)])
	assert.True(t, keys[k(2, 2000)])
	assert.True(t, keys[k(3, 3000)])
	assert.True(t, keys[k(4, 4000)])
	// Entries 5..9 should still be in the buffer.
	for _, r := range evicted {
		assert.NotEqual(t, k(5, 5000), r.Key)
		assert.NotEqual(t, k(9, 9000), r.Key)
	}
}

// TestBuffer_Discard: the condition-failed signal path. An entry is stored
// and then Discarded; no Ready is emitted and the message is released.
func TestBuffer_Discard(t *testing.T) {
	b := newTestBuffer()
	em := newTestMessage(8)
	_, done := b.AddFragment(k(1, 1000), em, Entry, 0, true, true)
	require.False(t, done)
	require.Equal(t, 1, b.Len())

	b.Discard(k(1, 1000))
	assert.Equal(t, 0, b.Len())
	assert.True(t, em.released)

	// Discard on an empty key is a no-op.
	b.Discard(k(42, 42))
}

// 23. Close() releases everything and returns Readys for in-flight entries.
func TestBuffer_Close(t *testing.T) {
	b := newTestBuffer()
	var msgs []*testMessage
	for i := uint64(1); i < 5; i++ {
		m := newTestMessage(8)
		msgs = append(msgs, m)
		_, _ = b.AddFragment(k(i, i*1000), m, Entry, 0, false, false)
	}

	readys := b.Close()
	require.Len(t, readys, 4)
	for _, r := range readys {
		assert.True(t, r.EntryTruncated, "incomplete entries should be flagged truncated")
		r.Entry.Release()
	}
	assert.Equal(t, 0, b.Len())
	for i, m := range msgs {
		assert.Truef(t, m.released, "message %d should be released", i)
	}
}
