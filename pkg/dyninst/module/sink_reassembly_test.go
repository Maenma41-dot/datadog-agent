// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package module

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/dyninst/decode"
	"github.com/DataDog/datadog-agent/pkg/dyninst/dispatcher"
	"github.com/DataDog/datadog-agent/pkg/dyninst/ir"
	"github.com/DataDog/datadog-agent/pkg/dyninst/output"
	"github.com/DataDog/datadog-agent/pkg/dyninst/symbol"
)

// buildTestEvent constructs a raw event byte slice from a header and data items.
// Each data item is a (DataItemHeader, []byte) pair. Stack trace is optional.
func buildTestEvent(header *output.EventHeader, stack []uint64, items []testDataItem) []byte {
	headerSize := int(unsafe.Sizeof(output.EventHeader{}))
	b := make([]byte, headerSize)
	*(*output.EventHeader)(unsafe.Pointer(&b[0])) = *header

	if len(stack) > 0 {
		stackBytes := unsafe.Slice((*byte)(unsafe.Pointer(&stack[0])), len(stack)*8)
		b = append(b, stackBytes...)
	}

	for _, item := range items {
		itemHeaderSize := int(unsafe.Sizeof(output.DataItemHeader{}))
		start := len(b)
		b = append(b, make([]byte, itemHeaderSize)...)
		*(*output.DataItemHeader)(unsafe.Pointer(&b[start])) = item.header
		b = append(b, item.data...)
		// Pad to 8-byte alignment.
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
	}

	// Fix up data_byte_len.
	(*output.EventHeader)(unsafe.Pointer(&b[0])).Data_byte_len = uint32(len(b))
	return b
}

type testDataItem struct {
	header output.DataItemHeader
	data   []byte
}

func TestHandleFragment_SingleFragmentFastPath(t *testing.T) {
	// A single-fragment event (seq=0, flags=0) should not be treated as
	// a continuation by IsContinuation(). This test verifies that the
	// fast path in HandleEvent skips reassembly entirely.
	h := &output.EventHeader{
		Continuation_seq:   0,
		Continuation_flags: 0,
	}
	require.False(t, h.IsContinuation())
}

func TestHandleFragment_TwoFragments(t *testing.T) {
	s := &sink{}

	rootItem := testDataItem{
		header: output.DataItemHeader{Type: 1, Length: 8, Address: 0x100},
		data:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	extraItem := testDataItem{
		header: output.DataItemHeader{Type: 2, Length: 4, Address: 0x200},
		data:   []byte{10, 11, 12, 13},
	}

	stack := []uint64{0xAAAA}

	// Fragment 0: first fragment, more to follow.
	frag0Header := output.EventHeader{
		Prog_id:            1,
		Goid:               42,
		Stack_byte_depth:   100,
		Probe_id:           7,
		Stack_byte_len:     8,
		Ktime_ns:           5000,
		Continuation_seq:   0,
		Continuation_flags: output.ContinuationFlagMore,
	}
	frag0 := buildTestEvent(&frag0Header, stack, []testDataItem{rootItem})

	msg0 := dispatcher.MakeTestingMessage(frag0)
	h0, err := msg0.Event().Header()
	require.NoError(t, err)

	list, done := s.handleFragment(msg0, h0)
	require.False(t, done, "first fragment should be buffered")
	require.Nil(t, list)
	require.Len(t, s.pending, 1)

	// Fragment 1: final fragment.
	frag1Header := output.EventHeader{
		Prog_id:            1,
		Goid:               42,
		Stack_byte_depth:   100,
		Probe_id:           7,
		Stack_byte_len:     0,
		Ktime_ns:           5000,
		Continuation_seq:   1,
		Continuation_flags: 0, // final
	}
	frag1 := buildTestEvent(&frag1Header, nil, []testDataItem{extraItem})

	msg1 := dispatcher.MakeTestingMessage(frag1)
	h1, err := msg1.Event().Header()
	require.NoError(t, err)

	list, done = s.handleFragment(msg1, h1)
	require.True(t, done, "final fragment should trigger reassembly")
	require.NotNil(t, list)
	require.Empty(t, s.pending, "pending should be cleared after reassembly")

	// Verify that iterating fragments yields both events with their data items.
	var allItems []output.DataItem
	for ev := range list.Fragments() {
		for item, err := range ev.DataItems() {
			require.NoError(t, err)
			allItems = append(allItems, item)
		}
	}
	require.Len(t, allItems, 2)
	require.Equal(t, uint32(1), allItems[0].Type())
	require.Equal(t, uint32(2), allItems[1].Type())

	// First fragment should have the stack trace.
	firstEv := list.event()
	pcs, err := firstEv.StackPCs()
	require.NoError(t, err)
	require.Equal(t, stack, pcs)
}

func TestHandleFragment_OrphanContinuation(t *testing.T) {
	s := &sink{}

	// Send a continuation fragment (seq=1) without a preceding first fragment.
	frag1Header := output.EventHeader{
		Goid:               42,
		Probe_id:           7,
		Ktime_ns:           5000,
		Continuation_seq:   1,
		Continuation_flags: 0,
	}
	frag1 := buildTestEvent(&frag1Header, nil, nil)
	msg := dispatcher.MakeTestingMessage(frag1)
	h, err := msg.Event().Header()
	require.NoError(t, err)

	list, done := s.handleFragment(msg, h)
	require.True(t, done, "orphan continuation should be immediately done")
	require.Nil(t, list, "orphan continuation should produce no list")
}

// TestContinuationEntryReturnPairing verifies that a multi-fragment entry event
// stored in the buffer tree survives until the return event pops it. This
// catches a bug where the continuation defer released the messageList after
// it had been transferred to the buffer tree.
func TestContinuationEntryReturnPairing(t *testing.T) {
	fakeDecoder := &stubDecoder{}
	mb := newBufferedMessageTracker(1 << 20) // 1MiB budget
	s := &sink{
		decoder:     fakeDecoder,
		tree:        mb.newTree(),
		logUploader: &stubLogUploader{},
		runtime: &runtimeImpl{
			procRuntimeIDbyProgramID: &sync.Map{},
		},
	}

	// Entry event fragment 0: has stack and root, expects return pairing.
	entryFrag0 := buildTestEvent(&output.EventHeader{
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  0,
		Stack_hash:                0x1234,
		Stack_byte_len:            8,
		Ktime_ns:                  5000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationReturnPairingExpected),
		Continuation_seq:          0,
		Continuation_flags:        output.ContinuationFlagMore,
	}, []uint64{0xAAAA}, nil)

	// Entry event fragment 1: final, no stack.
	entryFrag1 := buildTestEvent(&output.EventHeader{
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  0,
		Stack_hash:                0x1234,
		Ktime_ns:                  5000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationReturnPairingExpected),
		Continuation_seq:          1,
		Continuation_flags:        0, // final
	}, nil, nil)

	// Send both entry fragments.
	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(entryFrag0)))
	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(entryFrag1)))

	// The entry event should be stored in the buffer tree, NOT released.
	// If the defer bug is present, the messages would be released here
	// and the next step would panic.

	// Return event: expects to find the entry.
	returnEvent := buildTestEvent(&output.EventHeader{
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  0,
		Stack_hash:                0x5678,
		Ktime_ns:                  6000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationEntryPairingExpected),
	}, nil, nil)

	// Configure the decoder to count entry fragments during Decode (before
	// the entry chain is released by the defer).
	fakeDecoder.onDecode = func(event decode.Event) {
		for range event.EntryOrLine.Fragments() {
			fakeDecoder.entryFragmentCount++
		}
	}

	// This should NOT panic. With the defer bug, it would crash with
	// "nil pointer dereference" in popMatchingEvent -> totalSize.
	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(returnEvent)))

	// Verify the decoder was called and saw both entry fragments.
	require.Len(t, fakeDecoder.calls, 1)
	require.Equal(t, 2, fakeDecoder.entryFragmentCount,
		"entry should have 2 fragments when decoded")
}

// stubDecoder implements Decoder for testing.
type stubDecoder struct {
	calls              []decode.Event
	entryFragmentCount int
	onDecode           func(decode.Event) // called during Decode, before chain is released
}

func (d *stubDecoder) Decode(
	event decode.Event, _ symbol.Symbolicator, _ decode.MissingTypeCollector, out []byte,
) ([]byte, ir.ProbeDefinition, error) {
	d.calls = append(d.calls, event)
	if d.onDecode != nil {
		d.onDecode(event)
	}
	return []byte(`{}`), nil, nil
}

func (d *stubDecoder) ReportStackPCs(uint64, []uint64) {}

// stubLogUploader implements LogsUploader for testing.
type stubLogUploader struct{}

func (u *stubLogUploader) Enqueue(json.RawMessage) {}
func (u *stubLogUploader) Close()                  {}

func TestHandleFragment_EvictExpired(t *testing.T) {
	s := &sink{
		pending: make(map[fragmentKey]*pendingEvent),
	}

	// Insert an already-expired pending entry.
	expiredKey := fragmentKey{goid: 1, probeID: 1, ktimeNs: 1000}
	expiredMsg := dispatcher.MakeTestingMessage(buildTestEvent(&output.EventHeader{
		Goid: 1, Probe_id: 1, Ktime_ns: 1000,
	}, nil, nil))
	s.pending[expiredKey] = &pendingEvent{
		list:    newMessageList(expiredMsg),
		deadline: time.Now().Add(-1 * time.Second),
	}

	// Insert a still-valid pending entry.
	validKey := fragmentKey{goid: 2, probeID: 2, ktimeNs: 2000}
	validMsg := dispatcher.MakeTestingMessage(buildTestEvent(&output.EventHeader{
		Goid: 2, Probe_id: 2, Ktime_ns: 2000,
	}, nil, nil))
	s.pending[validKey] = &pendingEvent{
		list:    newMessageList(validMsg),
		deadline: time.Now().Add(1 * time.Minute),
	}

	// Trigger eviction by sending a new first fragment.
	newHeader := output.EventHeader{
		Goid:               99,
		Probe_id:           99,
		Ktime_ns:           9000,
		Continuation_seq:   0,
		Continuation_flags: output.ContinuationFlagMore,
	}
	newFrag := buildTestEvent(&newHeader, nil, nil)
	msg := dispatcher.MakeTestingMessage(newFrag)
	h, err := msg.Event().Header()
	require.NoError(t, err)

	s.handleFragment(msg, h)

	// Expired entry should be evicted; valid and new entries should remain.
	assert.NotContains(t, s.pending, expiredKey, "expired entry should be evicted")
	assert.Contains(t, s.pending, validKey, "valid entry should remain")
	newKey := fragmentKey{goid: 99, probeID: 99, ktimeNs: 9000}
	assert.Contains(t, s.pending, newKey, "new entry should be added")
}
