// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package module

import (
	"iter"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/dyninst/dispatcher"
	"github.com/DataDog/datadog-agent/pkg/dyninst/output"
)

// messageList is a pooled linked-list node holding a dispatcher.Message.
// A list of nodes represents the fragments of a single logical event.
// The common case (single-fragment event) is one node with next==nil.
// *messageList implements output.FragmentedEvent.
type messageList struct {
	msg  dispatcher.Message
	next *messageList
}

var messageListPool = sync.Pool{
	New: func() any { return new(messageList) },
}

func newMessageList(msg dispatcher.Message) *messageList {
	n := messageListPool.Get().(*messageList)
	n.msg = msg
	n.next = nil
	return n
}

// append adds a message to the end of the list.
func (n *messageList) append(msg dispatcher.Message) {
	tail := n
	for tail.next != nil {
		tail = tail.next
	}
	tail.next = newMessageList(msg)
}

// Fragments implements output.FragmentedEvent by yielding the event from each
// node in the list.
func (n *messageList) Fragments() iter.Seq[output.Event] {
	return func(yield func(output.Event) bool) {
		for cur := n; cur != nil; cur = cur.next {
			if !yield(cur.msg.Event()) {
				return
			}
		}
	}
}

// release releases all messages in the list and returns the nodes to the pool.
func (n *messageList) release() {
	for cur := n; cur != nil; {
		next := cur.next
		cur.msg.Release()
		cur.next = nil
		cur.msg = dispatcher.Message{}
		messageListPool.Put(cur)
		cur = next
	}
}

// totalSize returns the sum of event byte lengths across all fragments.
func (n *messageList) totalSize() int {
	size := 0
	for cur := n; cur != nil; cur = cur.next {
		size += len(cur.msg.Event())
	}
	return size
}

// event returns the event from the head node (first fragment).
func (n *messageList) event() output.Event {
	return n.msg.Event()
}
