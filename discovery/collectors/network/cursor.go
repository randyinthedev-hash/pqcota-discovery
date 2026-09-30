package network

import (
	"encoding/binary"
	"errors"
)

var errTruncated = errors.New("network: handshake bytes truncated")

// cursor — 경계 안전한 순차 바이트 리더. 모든 read는 (값, ok)로 실패를 노출한다.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, false
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, true
}

func (c *cursor) rest() []byte {
	out := c.b[c.pos:]
	c.pos = len(c.b)
	return out
}

func (c *cursor) u8() (uint8, bool) {
	v, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return v[0], true
}

func (c *cursor) u16() (uint16, bool) {
	v, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(v), true
}

func (c *cursor) u24() (uint32, bool) {
	v, ok := c.take(3)
	if !ok {
		return 0, false
	}
	return uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2]), true
}

func (c *cursor) u32() (uint32, bool) {
	v, ok := c.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

// vec — lenBytes(1|2) 길이 접두 벡터를 읽어 그 데이터를 돌려준다.
func (c *cursor) vec(lenBytes int) ([]byte, bool) {
	var n int
	switch lenBytes {
	case 1:
		v, ok := c.u8()
		if !ok {
			return nil, false
		}
		n = int(v)
	case 2:
		v, ok := c.u16()
		if !ok {
			return nil, false
		}
		n = int(v)
	default:
		return nil, false
	}
	return c.take(n)
}

func (c *cursor) skipVec(lenBytes int) bool {
	_, ok := c.vec(lenBytes)
	return ok
}

// readU16List — skipPrefix 바이트를 건너뛴 뒤 나머지를 u16 배열로 읽는다.
func readU16List(data []byte, skipPrefix int) []uint16 {
	if skipPrefix > len(data) {
		return nil
	}
	data = data[skipPrefix:]
	var out []uint16
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
