// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package eventbuf

import (
	"cmp"

	"github.com/google/btree"
)

// Side identifies which side of an invocation a fragment or drop notification
// refers to.
type Side uint8

// Side values.
const (
	Entry Side = iota
	Return
)

// Key identifies a single invocation. Goid, StackByteDepth, ProbeID are
// unique across concurrent calls (enforced BPF-side via in_progress_calls).
// EntryKtime further disambiguates rapid sequential invocations sharing
// the same triple.
type Key struct {
	Goid           uint64
	StackByteDepth uint32
	ProbeID        uint32
	EntryKtime     uint64
}

func cmpKey(a, b Key) int {
	return cmp.Or(
		cmp.Compare(a.Goid, b.Goid),
		cmp.Compare(a.StackByteDepth, b.StackByteDepth),
		cmp.Compare(a.ProbeID, b.ProbeID),
		cmp.Compare(a.EntryKtime, b.EntryKtime),
	)
}

// Ready is the result of finalizing an invocation: the fragments to decode,
// plus truncation flags so the caller can render an "incomplete" marker.
type Ready struct {
	Key   Key
	Entry *MessageList
	// Return is nil when the invocation had no return (standalone / inlined /
	// no-body probes) or when the return was lost entirely.
	Return *MessageList
	// EntryTruncated is set when some entry-side fragments didn't arrive due
	// to a ringbuf-full drop.
	EntryTruncated bool
	// ReturnTruncated is set when some return-side fragments didn't arrive.
	ReturnTruncated bool
	// ReturnLost is set when a RETURN_LOST notification arrived: the return
	// probe fired but its signal couldn't reach userspace. The entry is
	// complete; Return is nil.
	ReturnLost bool
}

// bufferedEvent is an in-progress invocation.
//
// Fragments accumulate in entry / returnList. The invocation is ready to
// finalize (i.e. a Ready should be returned) when:
//
//	entryExpected > 0 && entry.length == entryExpected
//	    &&
//	(!expectReturn || returnLost || (returnExpected > 0 && returnList.length == returnExpected))
//
// entryExpected / returnExpected are set by one of two paths: a fragment
// arriving with HasMoreFragments=false records its seq+1; a PARTIAL_ENTRY /
// PARTIAL_RETURN notification records last_seq+1. Either path may run first
// and the other then tops up. entryExpected==0 means "still assembling,
// we don't know the total yet".
type bufferedEvent struct {
	key Key

	entry          *MessageList
	entryFragments uint16
	entryExpected  uint16
	entryTruncated bool

	returnList       *MessageList
	returnFragments  uint16
	returnExpected   uint16
	returnTruncated  bool

	// expectReturn is true when we've learned this invocation has a return
	// (either from an entry fragment's pairing expectation or from a
	// RETURN_LOST notification). When false, finalization doesn't wait for
	// a return.
	expectReturn bool
	// returnLost: a RETURN_LOST notification was received. Finalize as soon
	// as the entry is complete; do not wait for any return fragments.
	returnLost bool

	// touch is a monotonic counter used by EvictStale to find the longest-
	// idle entries. It is updated on every mutation.
	touch uint64

	// finalized is set when Ready has been emitted for this key. Further
	// mutations via the normal path create a fresh entry (implicitly: the
	// old one has been removed). This flag is only reached if Close()
	// iterates a post-finalize entry; in normal operation the entry is
	// gone from the tree.
	finalized bool
}

// Buffer is the userspace-side event reassembly and pairing buffer.
//
// A single tree keyed by Key holds every in-flight invocation. Fragments
// and drop notifications both mutate tree entries; entries are finalized
// when they have enough state to emit.
//
// Not safe for concurrent use; the caller (sink) serializes access.
type Buffer struct {
	tree    *btree.BTreeG[*bufferedEvent]
	touchCt uint64
}

// NewBuffer returns an empty buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		tree: btree.NewG[*bufferedEvent](16, func(a, b *bufferedEvent) bool {
			return cmpKey(a.key, b.key) < 0
		}),
	}
}

// Len returns the number of in-flight invocations.
func (b *Buffer) Len() int {
	return b.tree.Len()
}

// AddFragment records a fragment belonging to the invocation identified by
// key. seq is the fragment's continuation_seq; isFinal is true when
// HasMoreFragments==false on the fragment's header; expectReturn is true
// when the fragment is an entry whose BPF header had ReturnPairingExpected.
// For return-side fragments, expectReturn is ignored.
//
// If this fragment completes the invocation, AddFragment returns (Ready,
// true) and the caller owns the MessageLists inside Ready. Otherwise it
// returns (Ready{}, false) and the Message is retained inside the buffer.
func (b *Buffer) AddFragment(
	key Key, msg Message, side Side, seq uint16, isFinal bool, expectReturn bool,
) (Ready, bool) {
	be := b.getOrCreate(key)
	b.touch(be)
	switch side {
	case Entry:
		if be.entry == nil {
			be.entry = NewMessageList(msg)
		} else {
			be.entry.Append(msg)
		}
		be.entryFragments++
		if isFinal && be.entryExpected == 0 {
			be.entryExpected = seq + 1
		}
		if expectReturn {
			be.expectReturn = true
		}
	case Return:
		if be.returnList == nil {
			be.returnList = NewMessageList(msg)
		} else {
			be.returnList.Append(msg)
		}
		be.returnFragments++
		if isFinal && be.returnExpected == 0 {
			be.returnExpected = seq + 1
		}
		be.expectReturn = true
	}
	return b.tryFinalize(be)
}

// NoteReturnLost records a RETURN_LOST drop notification: the return side
// had no fragments reach userspace. If the entry is already complete the
// invocation finalizes immediately.
func (b *Buffer) NoteReturnLost(key Key) (Ready, bool) {
	be := b.getOrCreate(key)
	b.touch(be)
	be.returnLost = true
	be.expectReturn = true
	return b.tryFinalize(be)
}

// NotePartial records a PARTIAL_ENTRY or PARTIAL_RETURN drop notification.
// lastSeq is the continuation_seq of the last fragment BPF successfully
// submitted on the indicated side; userspace should expect lastSeq+1
// fragments on that side and treat the resulting event as truncated.
func (b *Buffer) NotePartial(key Key, side Side, lastSeq uint16) (Ready, bool) {
	be := b.getOrCreate(key)
	b.touch(be)
	switch side {
	case Entry:
		if be.entryExpected == 0 {
			be.entryExpected = lastSeq + 1
		}
		be.entryTruncated = true
	case Return:
		if be.returnExpected == 0 {
			be.returnExpected = lastSeq + 1
		}
		be.returnTruncated = true
		be.expectReturn = true
	}
	return b.tryFinalize(be)
}

// EvictStale finalizes every invocation that hasn't been touched within the
// last maxIdle mutations, returning the resulting Ready values. Intended to
// be called periodically by the caller to bound memory usage when BPF sent
// partial fragments but a follow-up notification was lost, or vice versa.
//
// The returned slice may be empty. Callers own the MessageLists inside.
func (b *Buffer) EvictStale(maxIdle uint64) []Ready {
	if b.touchCt < maxIdle {
		return nil
	}
	cutoff := b.touchCt - maxIdle
	var toEvict []*bufferedEvent
	b.tree.Ascend(func(be *bufferedEvent) bool {
		if be.touch <= cutoff {
			toEvict = append(toEvict, be)
		}
		return true
	})
	if len(toEvict) == 0 {
		return nil
	}
	out := make([]Ready, 0, len(toEvict))
	for _, be := range toEvict {
		// Treat the eviction as a forced finalize. Mark whichever side is
		// incomplete as truncated so the caller knows the output is not
		// the full event.
		if be.entryExpected == 0 || be.entryFragments < be.entryExpected {
			be.entryTruncated = true
			if be.entryExpected == 0 {
				be.entryExpected = be.entryFragments
			}
		}
		if be.expectReturn && !be.returnLost {
			if be.returnExpected == 0 || be.returnFragments < be.returnExpected {
				be.returnTruncated = true
				if be.returnExpected == 0 {
					be.returnExpected = be.returnFragments
				}
			}
		}
		out = append(out, b.finalize(be))
	}
	return out
}

// Close finalizes every remaining invocation and returns their Readys. The
// caller owns the returned MessageLists and must Release them (or decode
// them) before discarding. Pending fragments with no matching notification
// are emitted as truncated.
//
// After Close the Buffer is empty; further use is a programmer error.
func (b *Buffer) Close() []Ready {
	if b.tree.Len() == 0 {
		return nil
	}
	out := make([]Ready, 0, b.tree.Len())
	b.tree.Ascend(func(be *bufferedEvent) bool {
		// Mimic EvictStale's best-effort completion logic.
		if be.entryExpected == 0 || be.entryFragments < be.entryExpected {
			be.entryTruncated = true
			if be.entryExpected == 0 {
				be.entryExpected = be.entryFragments
			}
		}
		if be.expectReturn && !be.returnLost {
			if be.returnExpected == 0 || be.returnFragments < be.returnExpected {
				be.returnTruncated = true
				if be.returnExpected == 0 {
					be.returnExpected = be.returnFragments
				}
			}
		}
		out = append(out, readyFrom(be))
		be.finalized = true
		return true
	})
	b.tree.Clear(true)
	return out
}

func (b *Buffer) getOrCreate(key Key) *bufferedEvent {
	if found, ok := b.tree.Get(&bufferedEvent{key: key}); ok {
		return found
	}
	be := &bufferedEvent{key: key}
	b.tree.ReplaceOrInsert(be)
	return be
}

func (b *Buffer) touch(be *bufferedEvent) {
	b.touchCt++
	be.touch = b.touchCt
}

// tryFinalize checks the finalization condition; if met, removes the entry
// from the tree and returns (Ready, true). Otherwise returns (Ready{}, false).
func (b *Buffer) tryFinalize(be *bufferedEvent) (Ready, bool) {
	entryReady := be.entryExpected > 0 && be.entryFragments == be.entryExpected
	if !entryReady {
		return Ready{}, false
	}
	if be.expectReturn && !be.returnLost {
		if be.returnExpected == 0 || be.returnFragments < be.returnExpected {
			return Ready{}, false
		}
	}
	return b.finalize(be), true
}

// finalize removes the entry from the tree and returns its Ready view.
func (b *Buffer) finalize(be *bufferedEvent) Ready {
	b.tree.Delete(be)
	return readyFrom(be)
}

func readyFrom(be *bufferedEvent) Ready {
	return Ready{
		Key:             be.key,
		Entry:           be.entry,
		Return:          be.returnList,
		EntryTruncated:  be.entryTruncated,
		ReturnTruncated: be.returnTruncated,
		ReturnLost:      be.returnLost,
	}
}
