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
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/dyninst/decode"
	"github.com/DataDog/datadog-agent/pkg/dyninst/dispatcher"
	"github.com/DataDog/datadog-agent/pkg/dyninst/eventbuf"
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

// newTestSink builds a minimal sink wired with stub decoder / log uploader
// and empty eventbuf stores. Suitable for tests that drive HandleEvent
// directly.
func newTestSink() (*sink, *stubDecoder) {
	dec := &stubDecoder{}
	budget := eventbuf.NewPairingBudget(1 << 20) // 1 MiB
	s := &sink{
		decoder:     dec,
		logUploader: &stubLogUploader{},
		pairing:     budget.NewStore(),
		reassembly:  eventbuf.NewReassemblyStore(),
		runtime: &runtimeImpl{
			procRuntimeIDbyProgramID: &sync.Map{},
		},
	}
	return s, dec
}

func TestHandleFragment_SingleFragmentFastPath(t *testing.T) {
	// A single-fragment event (seq=0, flags=0) is not a continuation.
	h := &output.EventHeader{
		Continuation_seq:   0,
		Continuation_flags: 0,
	}
	require.False(t, h.IsContinuation())
}

// TestHandleEvent_TwoFragmentEntryNoReturn verifies that a two-fragment event
// with no return pairing (e.g. a line probe) is reassembled and the decoder
// receives both fragments with their data items.
func TestHandleEvent_TwoFragmentEntryNoReturn(t *testing.T) {
	s, dec := newTestSink()

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
		Prog_id:                   1,
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  7,
		Stack_byte_len:            8,
		Ktime_ns:                  5000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationNone),
		Continuation_seq:          0,
		Continuation_flags:        output.ContinuationFlagMore,
	}
	frag0 := buildTestEvent(&frag0Header, stack, []testDataItem{rootItem})

	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(frag0)))
	// Decoder should not have been called yet.
	require.Empty(t, dec.calls)

	// Fragment 1: final fragment.
	frag1Header := output.EventHeader{
		Prog_id:                   1,
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  7,
		Stack_byte_len:            0,
		Ktime_ns:                  5000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationNone),
		Continuation_seq:          1,
		Continuation_flags:        0, // final
	}
	frag1 := buildTestEvent(&frag1Header, nil, []testDataItem{extraItem})

	// Iterate fragments inside onDecode, while the list is still alive.
	var allItems []output.DataItem
	dec.onDecode = func(ev decode.Event) {
		for ev := range ev.EntryOrLine.Fragments() {
			for item, err := range ev.DataItems() {
				if err == nil {
					allItems = append(allItems, item)
				}
			}
		}
	}

	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(frag1)))
	// Decoder should have been called once with the reassembled event.
	require.Len(t, dec.calls, 1)

	require.Len(t, allItems, 2)
	require.Equal(t, uint32(1), allItems[0].Type())
	require.Equal(t, uint32(2), allItems[1].Type())
}

// TestHandleEvent_OrphanContinuation verifies that a continuation fragment
// with no preceding first fragment is dropped silently.
func TestHandleEvent_OrphanContinuation(t *testing.T) {
	s, dec := newTestSink()

	// Send a continuation fragment (seq=1) without a preceding first fragment.
	frag1Header := output.EventHeader{
		Goid:               42,
		Probe_id:           7,
		Ktime_ns:           5000,
		Continuation_seq:   1,
		Continuation_flags: 0,
	}
	frag1 := buildTestEvent(&frag1Header, nil, nil)
	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(frag1)))
	assert.Empty(t, dec.calls, "orphan continuation should not produce a decode")
}

// TestContinuationEntryReturnPairing verifies that a multi-fragment entry
// event stored in the pairing store survives until the return event pops it.
// This is a regression test for an ownership bug where the continuation
// defer released the messageList after it had been transferred to the store.
func TestContinuationEntryReturnPairing(t *testing.T) {
	s, dec := newTestSink()

	// Entry event fragment 0: has stack, expects return pairing.
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

	// Return event: expects to find the entry.
	returnEvent := buildTestEvent(&output.EventHeader{
		Goid:                      42,
		Stack_byte_depth:          100,
		Probe_id:                  0,
		Stack_hash:                0x5678,
		Ktime_ns:                  6000,
		Event_pairing_expectation: uint8(output.EventPairingExpectationEntryPairingExpected),
	}, nil, nil)

	// Count entry fragments during Decode (before the entry list is released
	// by the defer).
	dec.onDecode = func(event decode.Event) {
		for range event.EntryOrLine.Fragments() {
			dec.entryFragmentCount++
		}
	}

	// Previously this panicked with a nil-pointer deref in the ownership-bug
	// variant. With eventbuf's store owning the list until Pop, it should
	// succeed and the decoder should see both entry fragments.
	require.NoError(t, s.HandleEvent(dispatcher.MakeTestingMessage(returnEvent)))

	require.Len(t, dec.calls, 1)
	require.Equal(t, 2, dec.entryFragmentCount,
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
