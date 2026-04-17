// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package eventbuf

import (
	"cmp"
	"sync"
	"time"

	"github.com/google/btree"
	"golang.org/x/time/rate"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// TODO: At some point we may want to add some fairness between different
// probes in the same process and between different processes. As currently
// implemented, if one process opens a bunch of functions that stay open for a
// long time, it will starve other processes of buffer space.

const (
	// Arbitrary degree for the btree. TODO: empirically determine the optimal degree.
	degree = 16
	// Arbitrary free list size: constant overhead plus some factor of the degree.
	freeListSize = 16
)

// PairingBudget tracks the memory usage of entry events waiting to be paired
// with their corresponding return events across many sinks.
//
// Each sink creates a PairingStore bound to a shared PairingBudget; the
// budget is enforced globally across all stores.
type PairingBudget struct {
	freelist  *btree.FreeListG[pairingEntry]
	byteLimit int
	mu        struct {
		sync.Mutex
		used int
	}
}

// NewPairingBudget returns a budget with the given byte limit shared across
// all stores that it backs.
func NewPairingBudget(byteLimit int) *PairingBudget {
	return &PairingBudget{
		freelist:  btree.NewFreeListG[pairingEntry](freeListSize),
		byteLimit: byteLimit,
	}
}

// NewStore returns a new store backed by this budget.
func (pb *PairingBudget) NewStore() *PairingStore {
	return &PairingStore{
		tree:   btree.NewWithFreeListG(degree, pairingEntryLess, pb.freelist),
		budget: pb,
	}
}

func (pb *PairingBudget) add(size int) (ok bool) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.mu.used+size > pb.byteLimit {
		return false
	}
	pb.mu.used += size
	return true
}

func (pb *PairingBudget) release(size int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.mu.used < size {
		log.Errorf("invariant violation: used %d < size %d", pb.mu.used, size)
		pb.mu.used = 0
		return
	}
	pb.mu.used -= size
}

// PairingKey identifies a single invocation of a probe.
//
// (Goid, StackByteDepth, ProbeID) is unique across concurrent calls
// (enforced BPF-side via in_progress_calls). EntryKtime further disambiguates
// rapid sequential invocations with the same triple so that a drop
// notification or late fragment for invocation N cannot affect invocation
// N+1's state.
type PairingKey struct {
	Goid           uint64
	StackByteDepth uint32
	ProbeID        uint32
	EntryKtime     uint64
}

type pairingEntry struct {
	key  PairingKey
	list *MessageList
}

func cmpPairingKey(a, b PairingKey) int {
	return cmp.Or(
		cmp.Compare(a.Goid, b.Goid),
		cmp.Compare(a.StackByteDepth, b.StackByteDepth),
		cmp.Compare(a.ProbeID, b.ProbeID),
		cmp.Compare(a.EntryKtime, b.EntryKtime),
	)
}

func pairingEntryLess(a, b pairingEntry) bool {
	return cmpPairingKey(a.key, b.key) < 0
}

// PairingStore holds entry events waiting for their return events.
type PairingStore struct {
	tree   *btree.BTreeG[pairingEntry]
	budget *PairingBudget
}

var duplicateEventLogLimiter = rate.NewLimiter(rate.Every(1*time.Minute), 10)

// Add stores list under key. Returns false if the shared byte budget would be
// exceeded and list could not be stored; the caller retains ownership of list
// and is responsible for releasing it.
//
// If an existing entry under key is replaced, the previous list is released
// and a duplicate-event warning is rate-limit-logged.
func (ps *PairingStore) Add(key PairingKey, list *MessageList) (ok bool) {
	size := list.TotalSize()
	if !ps.budget.add(size) {
		return false
	}
	if prev, ok := ps.tree.ReplaceOrInsert(pairingEntry{key: key, list: list}); ok {
		if duplicateEventLogLimiter.Allow() {
			log.Warnf(
				"duplicate event for goid %d, stackByteDepth %d, probeID %d, entryKtime %d",
				key.Goid, key.StackByteDepth, key.ProbeID, key.EntryKtime,
			)
		} else {
			log.Tracef(
				"duplicate event for goid %d, stackByteDepth %d, probeID %d, entryKtime %d",
				key.Goid, key.StackByteDepth, key.ProbeID, key.EntryKtime,
			)
		}
		ps.budget.release(prev.list.TotalSize())
		prev.list.Release()
	}
	return true
}

// Pop removes and returns the entry stored under key, if any.
func (ps *PairingStore) Pop(key PairingKey) (*MessageList, bool) {
	got, ok := ps.tree.Delete(pairingEntry{key: key})
	if !ok {
		return nil, false
	}
	ps.budget.release(got.list.TotalSize())
	return got.list, true
}

// Close releases every stored entry and empties the store.
func (ps *PairingStore) Close() {
	var toRelease int
	ps.tree.Ascend(func(e pairingEntry) bool {
		toRelease += e.list.TotalSize()
		e.list.Release()
		return true
	})
	ps.budget.release(toRelease)
	ps.tree.Clear(true)
}
