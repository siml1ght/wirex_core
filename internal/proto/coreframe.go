package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// neko core pipe framing: [len:2][type:1][ip:4][port:2][payload]
const CoreFrameHeaderSize = 9

const (
	CoreFrameFromGame byte = 0x01
	CoreFrameToGame   byte = 0x02
	CoreFrameClose    byte = 0x03
)

const MaxFrameSize = 65535

var (
	ErrFrameTooLarge   = fmt.Errorf("hydra-core: frame too large (max %d)", MaxFrameSize)
	ErrFrameTruncated  = fmt.Errorf("hydra-core: frame truncated")
	ErrFrameBadLength  = fmt.Errorf("hydra-core: bad frame length")
	ErrFrameBadVersion = fmt.Errorf("hydra-core: unknown frame type")
)

func WriteFrame(w io.Writer, frameType byte, addr [4]byte, port uint16, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	head := make([]byte, CoreFrameHeaderSize)
	binary.BigEndian.PutUint16(head[0:2], uint16(len(payload)))
	head[2] = frameType
	copy(head[3:7], addr[:])
	binary.BigEndian.PutUint16(head[7:9], port)
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) (frameType byte, addr [4]byte, port uint16, payload []byte, err error) {
	head := make([]byte, CoreFrameHeaderSize)
	if _, err = io.ReadFull(r, head); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(head[0:2]))
	frameType = head[2]
	copy(addr[:], head[3:7])
	port = binary.BigEndian.Uint16(head[7:9])
	switch frameType {
	case CoreFrameFromGame, CoreFrameToGame, CoreFrameClose:
	default:
		err = fmt.Errorf("%w: 0x%02X", ErrFrameBadVersion, frameType)
		return
	}
	if length > MaxFrameSize {
		err = ErrFrameTooLarge
		return
	}
	if frameType == CoreFrameClose && length != 0 {
		err = ErrFrameBadLength
		return
	}
	if length > 0 {
		payload = make([]byte, length)
		if _, err = io.ReadFull(r, payload); err != nil {
			err = fmt.Errorf("%w: %v", ErrFrameTruncated, err)
			return
		}
	}
	return
}
