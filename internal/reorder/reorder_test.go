package reorder

import (
	"reflect"
	"testing"
)

func TestSerialOrderingAndWraparound(t *testing.T) {
	var got []uint32
	b := New[uint32]()
	deliver := func(seq uint32, v uint32) {
		got = append(got, v)
	}
	b.Push(0xFFFFFFFD, 0xFFFFFFFD, deliver)
	b.Push(0x00000001, 0x00000001, deliver)
	b.Push(0x00000000, 0x00000000, deliver)
	b.Push(0xFFFFFFFE, 0xFFFFFFFE, deliver)
	b.Push(0xFFFFFFFF, 0xFFFFFFFF, deliver)
	want := []uint32{0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	b.Push(0xFFFFFFFD, 99, deliver)
	if len(got) != 5 {
		t.Fatalf("replay прошёл: %v", got)
	}
}

func TestGapBuffering(t *testing.T) {
	var got []uint32
	b := New[uint32]()
	deliver := func(seq uint32, v uint32) {
		got = append(got, v)
	}
	b.Push(1, 1, deliver)
	b.Push(3, 3, deliver)
	if !reflect.DeepEqual(got, []uint32{1}) {
		t.Fatalf("после 1 и 3: %v", got)
	}
	b.Push(2, 2, deliver)
	if !reflect.DeepEqual(got, []uint32{1, 2, 3}) {
		t.Fatalf("после закрытия гэпа: %v", got)
	}
	b.Push(5, 5, deliver)
	if len(got) != 3 {
		t.Fatalf("seq=5 не должен доставляться до 4: %v", got)
	}
	b.Push(4, 4, deliver)
	if !reflect.DeepEqual(got, []uint32{1, 2, 3, 4, 5}) {
		t.Fatalf("после 4: %v", got)
	}
}

func TestReplayAndOverflowDropped(t *testing.T) {
	var got []uint32
	b := New[uint32]()
	deliver := func(seq uint32, v uint32) {
		got = append(got, v)
	}
	b.Push(1, 1, deliver)
	b.Push(2, 2, deliver)
	b.Push(3, 3, deliver)
	b.Push(1, 1, deliver)
	b.Push(2, 2, deliver)
	if !reflect.DeepEqual(got, []uint32{1, 2, 3}) {
		t.Fatalf("дубликаты прошли: %v", got)
	}
	b.Push(3+DefaultWindow, 99, deliver)
	if !reflect.DeepEqual(got, []uint32{1, 2, 3}) {
		t.Fatalf("пакет из-за окна прошёл: %v", got)
	}
	if !SeqBefore(3, 4) || SeqBefore(4, 3) || SeqBefore(4, 4) {
		t.Fatal("ошибка сериальной арифметики RFC 1982")
	}
	if !SeqBefore(0xFFFFFFFF, 0) {
		t.Fatal("wrap-around 0xFFFFFFFF -> 0 не определён как 'раньше'")
	}
}
