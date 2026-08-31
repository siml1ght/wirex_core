package reorder

import "sync"

// 4096 seqs of slack covers any realistic jitter; a seq further ahead is treated as junk
const DefaultWindow = 4096

// cast to int32 implements uint32 wrap-around per rfc 1982
func SeqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

func SeqAtOrBefore(a, b uint32) bool {
	return a == b || SeqBefore(a, b)
}

type Buffer[T any] struct {
	mu      sync.Mutex
	started bool
	next    uint32
	buf     map[uint32]T
}

func New[T any]() *Buffer[T] {
	return &Buffer[T]{buf: make(map[uint32]T)}
}

// in-order seqs deliver immediately; gaps buffer; replays die here before any side effect
func (b *Buffer[T]) Push(seq uint32, item T, deliver func(seq uint32, item T)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		b.started = true
		b.next = seq
	}
	if SeqBefore(seq, b.next) {
		return
	}
	if seq-b.next >= DefaultWindow {
		return
	}
	if _, dup := b.buf[seq]; dup {
		return
	}
	if seq != b.next {
		b.buf[seq] = item
		return
	}
	deliver(seq, item)
	b.next++
	for {
		buffered, ok := b.buf[b.next]
		if !ok {
			break
		}
		delete(b.buf, b.next)
		deliver(b.next, buffered)
		b.next++
	}
}
