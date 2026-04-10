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

// fragmentKey identifies a logical event whose data may span multiple ringbuf
// submissions (continuation fragments).
type fragmentKey struct {
	goid           uint64
	stackByteDepth uint32
	probeID        uint32
	ktimeNs        uint64
}

// pendingEvent holds the message list for fragments being reassembled.
type pendingEvent struct {
	list    *messageList // linked list of fragment messages
	lastSeq  uint16        // highest continuation_seq seen
	deadline time.Time     // eviction deadline for incomplete reassembly
}

const (
	// fragmentTimeout is how long we wait for continuation fragments before
	// evicting an incomplete set. All fragments from a single probe invocation
	// are produced in microseconds; this timeout is very generous.
	fragmentTimeout = 100 * time.Millisecond
	// maxPendingFragmentSets caps the number of in-flight reassembly sets to
	// bound memory usage.
	maxPendingFragmentSets = 64
)

type sink struct {
	runtime      *runtimeImpl
	decoder      Decoder
	symbolicator symbol.Symbolicator
	programID    ir.ProgramID
	processID    actuator.ProcessID
	service      string
	processTags  string
	logUploader  LogsUploader
	tree         *bufferTree
	missingTypes missingTypeTracker

	// Probes is an ordered list of probes. The event header's probe_id is an
	// index into this list.
	probes []*ir.Probe

	// pending holds fragment sets being reassembled from multi-fragment events.
	pending map[fragmentKey]*pendingEvent
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
	defer func() {
		if msg != (dispatcher.Message{}) {
			msg.Release()
		}
	}()

	msgEvent := msg.Event()
	evHeader, err := msgEvent.Header()
	if err != nil {
		return fmt.Errorf("error getting event header: %w", err)
	}

	// Handle multi-fragment continuation events. Non-final fragments are
	// buffered; the final fragment triggers reassembly and falls through
	// to the normal event processing path below.
	//
	// msgList holds the messageList for the current message (continuation
	// or single-fragment). For continuation events, it's built by
	// handleFragment. For single-fragment events that need to be stored in
	// the buffer tree, it's created on demand below.
	var msgList *messageList
	var releaseMsgList = true // set to false if ownership transfers to buffer tree
	if evHeader.IsContinuation() {
		list, done := s.handleFragment(msg, evHeader)
		if !done {
			msg = dispatcher.Message{} // held in pending list
			return nil
		}
		if list == nil {
			return nil // orphan continuation, discarded
		}
		msgList = list
		defer func() {
			if releaseMsgList && msgList != nil {
				msgList.release()
			}
		}()
		msg = dispatcher.Message{} // prevent double-release by outer defer

		msgEvent = msgList.event() // first fragment
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
	// entryFragmented and returnFragmented are the FragmentedEvent values
	// passed to the decoder. They may be a *messageList (for multi-fragment
	// or buffer-tree-stored events) or a SingleEvent (for single-fragment
	// events where the message is released by the outer defer).
	var entryFragmented, returnFragmented output.FragmentedEvent
	switch output.EventPairingExpectation(evHeader.Event_pairing_expectation) {
	case output.EventPairingExpectationEntryPairingExpected:
		entryChain, ok := s.tree.popMatchingEvent(eventKey{
			goid:           evHeader.Goid,
			stackByteDepth: evHeader.Stack_byte_depth,
			probeID:        evHeader.Probe_id,
		})
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
		defer entryChain.release()
		entryFragmented = entryChain
		if msgList != nil {
			returnFragmented = msgList
		} else {
			returnFragmented = output.SingleEvent(msgEvent)
		}
	case output.EventPairingExpectationReturnPairingExpected:
		// Store the entry event (possibly multi-fragment) in the buffer tree
		// for later pairing with the return event.
		if msgList == nil {
			msgList = newMessageList(msg)
		}
		if s.tree.addEvent(eventKey{
			goid:           evHeader.Goid,
			stackByteDepth: evHeader.Stack_byte_depth,
			probeID:        evHeader.Probe_id,
		}, msgList) {
			// Record stack PCs for later use when the return event arrives.
			if stackPCs, err := msgEvent.StackPCs(); err == nil {
				s.decoder.ReportStackPCs(evHeader.Stack_hash, slices.Clone(stackPCs))
			}
			msg = dispatcher.Message{}      // prevent release; owned by list
			releaseMsgList = false          // prevent release by continuation defer
			return nil
		}
		// addEvent failed (buffer full). Release the list we just created
		// for the single-message case, then fall through to emit directly.
		if !evHeader.IsContinuation() {
			msgList.release()
			msgList = nil
		}

		// If the buffer was full, mark the event to inform the user, and output
		// it directly.
		evHeader.Event_pairing_expectation =
			uint8(output.EventPairingExpectationBufferFull)
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingBufferFull,
			eventPairingBufferFullLogLimiter,
			"userspace buffer capacity exceeded",
		)
		if msgList != nil {
			entryFragmented = msgList
		} else {
			entryFragmented = output.SingleEvent(msgEvent)
		}
	case output.EventPairingExpectationCallMapFull:
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingCallMapFull,
			eventPairingCallMapFullLogLimiter,
			"call map capacity exceeded",
		)
		if msgList != nil {
			entryFragmented = msgList
		} else {
			entryFragmented = output.SingleEvent(msgEvent)
		}
	case output.EventPairingExpectationCallCountExceeded:
		recordEventPairingIssue(
			&s.runtime.stats.eventPairingCallCountExceeded,
			eventPairingCallCountExceededLogLimiter,
			"maximum call count exceeded",
		)
		if msgList != nil {
			entryFragmented = msgList
		} else {
			entryFragmented = output.SingleEvent(msgEvent)
		}
	case output.EventPairingExpectationConditionFailed:
		entryChain, ok := s.tree.popMatchingEvent(eventKey{
			goid:           evHeader.Goid,
			stackByteDepth: evHeader.Stack_byte_depth,
			probeID:        evHeader.Probe_id,
		})
		if ok {
			entryChain.release()
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
		if msgList != nil {
			entryFragmented = msgList
		} else {
			entryFragmented = output.SingleEvent(msgEvent)
		}
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

// handleFragment processes a continuation fragment. It returns (nil, false) when
// the fragment has been buffered and more fragments are expected. It returns
// (list, true) when reassembly is complete. It returns (nil, true) when the
// fragment is an orphan (no matching first fragment).
func (s *sink) handleFragment(msg dispatcher.Message, h *output.EventHeader) (*messageList, bool) {
	if s.pending == nil {
		s.pending = make(map[fragmentKey]*pendingEvent)
	}

	key := fragmentKey{
		goid:           h.Goid,
		stackByteDepth: h.Stack_byte_depth,
		probeID:        h.Probe_id,
		ktimeNs:        h.Ktime_ns,
	}

	isFinal := !h.HasMoreFragments()

	if h.Continuation_seq == 0 {
		// First fragment: start a new list.
		s.evictExpiredFragments()
		s.pending[key] = &pendingEvent{
			list:    newMessageList(msg),
			lastSeq:  0,
			deadline: time.Now().Add(fragmentTimeout),
		}
		if isFinal {
			// seq=0 and no more fragments, but IsContinuation() was true,
			// which shouldn't happen. Treat as complete single event.
			pe := s.pending[key]
			delete(s.pending, key)
			return pe.list, true
		}
		return nil, false
	}

	// Continuation fragment (seq > 0).
	pe, ok := s.pending[key]
	if !ok {
		// First fragment was lost — discard this continuation.
		log.Tracef("orphan continuation fragment seq=%d for goid=%d probe=%d",
			h.Continuation_seq, h.Goid, h.Probe_id)
		return nil, true
	}

	pe.list.append(msg)
	pe.lastSeq = h.Continuation_seq

	if !isFinal {
		return nil, false
	}

	// Final fragment received — return the complete list.
	delete(s.pending, key)
	return pe.list, true
}

// evictExpiredFragments removes incomplete fragment sets that have passed their
// deadline. Called periodically when new first-fragments arrive.
func (s *sink) evictExpiredFragments() {
	if len(s.pending) == 0 {
		return
	}
	now := time.Now()
	for key, pe := range s.pending {
		if now.After(pe.deadline) {
			log.Tracef("evicting expired fragment set for goid=%d probe=%d (seq=%d)",
				key.goid, key.probeID, pe.lastSeq)
			pe.list.release()
			delete(s.pending, key)
		}
	}
	// If still over the cap, evict the oldest entries.
	for len(s.pending) >= maxPendingFragmentSets {
		var oldestKey fragmentKey
		var oldestDeadline time.Time
		for key, pe := range s.pending {
			if oldestDeadline.IsZero() || pe.deadline.Before(oldestDeadline) {
				oldestKey = key
				oldestDeadline = pe.deadline
			}
		}
		if pe, ok := s.pending[oldestKey]; ok {
			pe.list.release()
		}
		delete(s.pending, oldestKey)
	}
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
	s.tree.close()
}
