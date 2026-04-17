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

func budgetUsed(pb *PairingBudget) int {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	return pb.mu.used
}

func makeList(size int) *MessageList {
	return NewMessageList(newTestMessage(size))
}

func TestPairingStoreAddAndPop(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()
	defer ps.Close()

	key := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5}

	ok := ps.Add(key, makeList(64))
	require.True(t, ok)
	assert.Equal(t, 64, budgetUsed(pb))

	list, ok := ps.Pop(key)
	require.True(t, ok)
	assert.Equal(t, 64, len(list.Head()))
	assert.Equal(t, 0, budgetUsed(pb))
	list.Release()
}

func TestPairingStorePopMissing(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()
	defer ps.Close()

	key := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5}
	_, ok := ps.Pop(key)
	assert.False(t, ok)
	assert.Equal(t, 0, budgetUsed(pb))
}

func TestPairingStoreBudgetFull(t *testing.T) {
	pb := NewPairingBudget(100)
	ps := pb.NewStore()
	defer ps.Close()

	key1 := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5}
	require.True(t, ps.Add(key1, makeList(80)))
	assert.Equal(t, 80, budgetUsed(pb))

	// 80 + 80 > 100 — should fail.
	key2 := PairingKey{Goid: 2, StackByteDepth: 100, ProbeID: 5}
	assert.False(t, ps.Add(key2, makeList(80)))
	assert.Equal(t, 80, budgetUsed(pb))
}

// Regression test: inserting a duplicate must account for the size change.
func TestPairingStoreDuplicateAccounting(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()
	defer ps.Close()

	key := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5}
	require.True(t, ps.Add(key, makeList(64)))
	assert.Equal(t, 64, budgetUsed(pb))

	require.True(t, ps.Add(key, makeList(48)), "duplicate should return true")
	assert.Equal(t, 48, budgetUsed(pb),
		"used should reflect the replacement size")

	list, ok := ps.Pop(key)
	require.True(t, ok)
	assert.Equal(t, 48, len(list.Head()))
	assert.Equal(t, 0, budgetUsed(pb))
	list.Release()
}

func TestPairingStoreDuplicateSameSize(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()
	defer ps.Close()

	key := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5}

	require.True(t, ps.Add(key, makeList(64)))
	require.True(t, ps.Add(key, makeList(64)))
	assert.Equal(t, 64, budgetUsed(pb))

	list, ok := ps.Pop(key)
	require.True(t, ok)
	assert.Equal(t, 64, len(list.Head()))
	assert.Equal(t, 0, budgetUsed(pb))
	list.Release()
}

func TestPairingStoreCloseReleasesBudget(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()

	keys := []PairingKey{
		{Goid: 1, StackByteDepth: 10, ProbeID: 1},
		{Goid: 2, StackByteDepth: 20, ProbeID: 2},
		{Goid: 3, StackByteDepth: 30, ProbeID: 3},
	}
	for _, k := range keys {
		require.True(t, ps.Add(k, makeList(32)))
	}
	assert.Equal(t, 96, budgetUsed(pb))

	ps.Close()
	assert.Equal(t, 0, budgetUsed(pb),
		"close must release all tracked bytes")
}

// TestPairingStoreEntryKtimeDistinguishesInvocations verifies that two entries
// sharing (goid, depth, probeID) but differing by EntryKtime are stored as
// independent rows in the tree. This is the correlation-ID mechanism that
// prevents late drop notifications for invocation N from affecting invocation
// N+1 state.
func TestPairingStoreEntryKtimeDistinguishesInvocations(t *testing.T) {
	pb := NewPairingBudget(1024)
	ps := pb.NewStore()
	defer ps.Close()

	k1 := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5, EntryKtime: 1000}
	k2 := PairingKey{Goid: 1, StackByteDepth: 100, ProbeID: 5, EntryKtime: 2000}
	require.True(t, ps.Add(k1, makeList(32)))
	require.True(t, ps.Add(k2, makeList(64)))
	assert.Equal(t, 96, budgetUsed(pb))

	// Pop k1: k2 remains.
	list, ok := ps.Pop(k1)
	require.True(t, ok)
	assert.Equal(t, 32, len(list.Head()))
	list.Release()
	assert.Equal(t, 64, budgetUsed(pb))

	list, ok = ps.Pop(k2)
	require.True(t, ok)
	assert.Equal(t, 64, len(list.Head()))
	list.Release()
	assert.Equal(t, 0, budgetUsed(pb))
}

func TestPairingStoreMultipleStoresShareBudget(t *testing.T) {
	pb := NewPairingBudget(128)
	ps1 := pb.NewStore()
	ps2 := pb.NewStore()
	defer ps1.Close()
	defer ps2.Close()

	key1 := PairingKey{Goid: 1, StackByteDepth: 10, ProbeID: 1}
	key2 := PairingKey{Goid: 2, StackByteDepth: 20, ProbeID: 2}

	require.True(t, ps1.Add(key1, makeList(64)))
	require.True(t, ps2.Add(key2, makeList(64)))
	assert.Equal(t, 128, budgetUsed(pb))

	// Budget is full; a third add on either store should fail.
	key3 := PairingKey{Goid: 3, StackByteDepth: 30, ProbeID: 3}
	assert.False(t, ps1.Add(key3, makeList(1)))

	// Releasing from one store frees space for the other.
	list, ok := ps1.Pop(key1)
	require.True(t, ok)
	list.Release()
	assert.Equal(t, 64, budgetUsed(pb))

	require.True(t, ps1.Add(key3, makeList(32)))
	assert.Equal(t, 96, budgetUsed(pb))
}
