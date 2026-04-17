// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package module

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/DataDog/datadog-agent/pkg/dyninst/actuator"
	"github.com/DataDog/datadog-agent/pkg/dyninst/decode"
	"github.com/DataDog/datadog-agent/pkg/dyninst/dispatcher"
	"github.com/DataDog/datadog-agent/pkg/dyninst/eventbuf"
	"github.com/DataDog/datadog-agent/pkg/dyninst/ir"
	"github.com/DataDog/datadog-agent/pkg/dyninst/output"
	"github.com/DataDog/datadog-agent/pkg/dyninst/symbol"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// missingTypeTracker collects type names that the decoder encounters in
// interface values but cannot find in the IR type registry. It implements
// decode.MissingTypeCollector and is drained by the sink after each Decode.
type missingTypeTracker struct {
	typeSet map[string]struct{}
	nameBuf []string
}

// RecordMissingType implements decode.MissingTypeCollector.
func (t *missingTypeTracker) RecordMissingType(typeName string) {
	if t.typeSet == nil {
		t.typeSet = make(map[string]struct{})
	}
	t.typeSet[typeName] = struct{}{}
}

// drain returns the accumulated type names and resets the tracker.
// Returns nil if no types were collected. The returned slice is valid
// only until the next call to drain.
func (t *missingTypeTracker) drain() []string {
	if len(t.typeSet) == 0 {
		return nil
	}
	for name := range t.typeSet {
		t.nameBuf = append(t.nameBuf, name)
	}
	clear(t.typeSet)
	sort.Strings(t.nameBuf)
	ret := t.nameBuf
	t.nameBuf = t.nameBuf[:0]
	return ret
}

type sink struct {
	runtime      *runtimeImpl
	decoder      Decoder
	symbolicator symbol.Symbolicator
	programID    ir.ProgramID
	processID    actuator.ProcessID
	service      string
	processTags  string
	logUploader  LogsUploader
	pairing      *eventbuf.PairingStore
	reassembly   *eventbuf.ReassemblyStore
	missingTypes missingTypeTracker

	// Probes is an ordered list of probes. The event header's probe_id is an
	// index into this list.
	probes []*ir.Probe
}

var _ dispatcher.Sink = &sink{}

// We don't want to be too noisy about decoding errors, but we do want to learn
// about them and we don't want to bail out completely.
var decodingErrorLogLimiter = rate.NewLimiter(rate.Every(1*time.Minute), 10)

var noMatchingEventLogLimiter = rate.NewLimiter(rate.Every(10*time.Minute), 10)
var eventPairingBufferFullLogLimiter = rate.NewLimiter(rate.Every(10*time.Minute), 10)
var eventPairingCallMapFullLogLimiter = rate.NewLimiter(rate.Every(10*time.Minute), 10)
var eventPairingCallCountExceededLogLimiter = rate.NewLimiter(rate.Every(10*time.Minute), 10)
var eventPairingConditionFailedLogLimiter = rate.NewLimiter(rate.Every(10*time.Minute), 10)

func (s *sink) HandleEvent(msg dispatcher.Message) error {
	// msgOwned tracks whether msg is still ours to release at the end of
	// HandleEvent. Transfer of ownership to a messageList flips it to false.
	msgOwned := true
	defer func() {
		if msgOwned && msg != (dispatcher.Message{}) {
			msg.Release()
		}
	}()

	msgEvent := msg.Event()
	evHeader, err := msgEvent.Header()
	if err != nil {
		return fmt.Errorf("error getting event header: %w", err)
	}

	// Handle multi-fragment continuation events. Non-final fragments are
	// buffered; the final fragment triggers reassembly and falls through to
	// the normal event processing path below.
	//
	// msgList holds the reassembled fragment list when we have one: either
	// from the reassembly store (continuation) or from wrapping a single
	// message for storage in the pairing store. nil when the event is
	// single-fragment and we plan to emit directly.
	var msgList *eventbuf.MessageList
	releaseMsgList := true // cleared when ownership transfers to pairing store
	if evHeader.IsContinuation() {
		list, done := s.reassembly.AddFragment(
			eventbuf.FragmentKey{
				Goid:           evHeader.Goid,
				StackByteDepth: evHeader.Stack_byte_depth,
				ProbeID:        evHeader.Probe_id,
				KtimeNs:        evHeader.Ktime_ns,
			},
			wrapMessage(msg),
			evHeader.Continuation_seq,
			!evHeader.HasMoreFragments(),
		)
		msgOwned = false // ownership handed to the reassembly store
		if !done {
			return nil
		}
		if list == nil {
			return nil // orphan continuation, discarded
		}
		msgList = list
		defer func() {
			if releaseMsgList && msgList != nil {
				msgList.Release()
			}
		}()

		msgEvent = msgList.Head() // first fragment for header/stack access
		var rerr error
		evHeader, rerr = msgEvent.Header()
		if rerr != nil {
			return fmt.Errorf("error reading reassembled event header: %w", rerr)
		}
	}

	var (
		decodedBytes []byte
		probe        ir.ProbeDefinition
	)

	recordEventPairingIssue := func(
		stats *atomic.Uint64, limiter *rate.Limiter, issueMsg string,
	) {
		stats.Add(1)
		var probeID string
		if int(evHeader.Probe_id) < len(s.probes) {
			probeID = s.probes[evHeader.Probe_id].GetID()
		} else {
			probeID = fmt.Sprintf("unknown probeID %d", evHeader.Probe_id)
		}
		const format = "event pairing issue for probe %s: %s"
		if limiter.Allow() {
			log.Infof(format, probeID, issueMsg)
		} else {
			log.Tracef(format, probeID, issueMsg)
		}
	}
	// fragmentedFromSingleton returns an output.FragmentedEvent view of the
	// single message held in msg (when msgList is nil). Relies on msg still
	// being owned by HandleEvent's defer.
	fragmentedFromSingleton := func() output.FragmentedEvent {
		if msgList != nil {
			return msgList
		}
		return output.SingleEvent(msgEvent)
	}
	pairingKey := eventbuf.PairingKey{
		Goid:           evHeader.Goid,
		StackByteDepth: evHeader.Stack_byte_depth,
		ProbeID:        evHeader.Probe_id,
		EntryKtime:     evHeader.Entry_ktime_ns,
	}
	var entryFragmented, returnFragmented output.FragmentedEvent
	switch output.EventPairingExpectation(evHeader.Event_pairing_expectation) {
	case output.EventPairingExpectationEntryPairingExpected:
		entryList, ok := s.pairing.Pop(pairingKey)
		// We expected to find a matching entry event but didn't. This could
		// happen if we ran out of buffer space for the entry event.
		if !ok {
			if noMatchingEventLogLimiter.Allow() {
				log.Warnf(
					"no matching event for goid %d, stackByteDepth %d, probeID %d",
					evHeader.Goid, evHeader.Stack_byte_depth, evHeader.Probe_id,
				)
			} else {
				log.Tracef(
					"no matching event for goid %d, stackByteDepth %d, probeID %d",
					evHeader.Goid, evHeader.Stack_byte_depth, evHeader.Probe_id,
				)
			}
			return nil
		}
		defer entryList.Release()
		entryFragmented = entryList
		returnFragmented = fragmentedFromSingleton()
	case output.EventPairingExpectationReturnPairingExpected:
		// Store the entry event (possibly multi-fragment) in the pairing store
		// for later pairing with the return event.
		if msgList == nil {
			msgList = eventbuf.NewMessageList(wrapMessage(msg))
			msgOwned = false
		}
		if s.pairing.Add(pairingKey, msgList) {
			// Record stack PCs for later use when the return event arrives.
			if stackPCs, err := msgEvent.StackPCs(); err == nil {
				s.decoder.ReportStackPCs(evHeader.Stack_hash, slices.Clone(stackPCs))
			}
			releaseMsgList = false
			return nil
		}
		// Add failed (budget full). Release the list we just wrapped around
		// the single message; fall through to emit directly.
		if !evHeader.IsContinuation() {
			msgList.Release()
			msgList = nil
		}
		evHeader.Event_pairing_expectation =
			uint8(output.EventPairingExpectationBufferFull)
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingBufferFull,
			eventPairingBufferFullLogLimiter,
			"userspace buffer capacity exceeded",
		)
		entryFragmented = fragmentedFromSingleton()
	case output.EventPairingExpectationCallMapFull:
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingCallMapFull,
			eventPairingCallMapFullLogLimiter,
			"call map capacity exceeded",
		)
		entryFragmented = fragmentedFromSingleton()
	case output.EventPairingExpectationCallCountExceeded:
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingCallCountExceeded,
			eventPairingCallCountExceededLogLimiter,
			"maximum call count exceeded",
		)
		entryFragmented = fragmentedFromSingleton()
	case output.EventPairingExpectationConditionFailed:
		if entryList, ok := s.pairing.Pop(pairingKey); ok {
			entryList.Release()
		}
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingConditionFailed,
			eventPairingConditionFailedLogLimiter,
			"return condition failed",
		)
		return nil
	case output.EventPairingExpectationNone,
		output.EventPairingExpectationNoneInlined,
		output.EventPairingExpectationNoneNoBody:
		entryFragmented = fragmentedFromSingleton()
	default:
		return fmt.Errorf("unknown event pairing expectation: %d", evHeader.Event_pairing_expectation)
	}
	decodedBytes, probe, err = s.decoder.Decode(decode.Event{
		EntryOrLine: entryFragmented,
		Return:      returnFragmented,
		ServiceName: s.service,
		ProcessTags: s.processTags,
	}, s.symbolicator, &s.missingTypes, decodedBytes)
	if err != nil {
		if probe != nil {
			if reported := s.runtime.reportProbeError(
				s.programID, probe, err, "DecodeFailed",
			); reported {
				log.Warnf(
					"failed to report probe error for probe %s in service %s: %v",
					probe.GetID(), s.service, err,
				)
			}
			return nil
		}
		if decodingErrorLogLimiter.Allow() {
			log.Warnf(
				"failed to decode event in service %s: %v",
				s.service, err,
			)
		} else {
			log.Tracef(
				"failed to decode event in service %s: %v",
				s.service, err,
			)
		}
		// TODO: Report failures to the controller to remove the relevant probe
		// or program.
		return nil
	}
	s.runtime.setProbeMaybeEmitting(s.programID, probe)
	if missingTypes := s.missingTypes.drain(); len(missingTypes) > 0 {
		s.runtime.actuator.ReportMissingTypes(s.processID, missingTypes)
	}
	s.logUploader.Enqueue(decodedBytes)
	return nil
}

// HandleDropNotification receives a side-channel drop notification for one
// of this sink's probes. This commit installs a stub; task 27 drains the
// notification through an eventbuf-backed flow that salvages partial data
// and emits entry-only when the return is lost.
func (s *sink) HandleDropNotification(n output.DropNotification) {
	// TODO(task 27): process via eventbuf.
	_ = n
}

func (s *sink) Close() {
	if s.logUploader != nil {
		s.logUploader.Close()
	}
	if closer, ok := s.symbolicator.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.Warnf("failed to close symbolicator: %v", err)
		}
	}
	s.pairing.Close()
	s.reassembly.Close()
}
