// Package nonce provides ACME nonce generation and verification.
//
// Spend tracking is entirely in memory, and nonce lifetime depends on spend
// rate, to keep memory requirements constant.
//
// Read-only consumers that can tolerate replays don't need to share state with
// the write consumer, but by sharing a key they can mint nonces that the write
// consumer will accept.
package nonce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
	"uuid"
)

type Issuer struct {
	key [32]byte
}

func NewIssuer(key []byte) (*Issuer, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	var g Issuer
	copy(g.key[:], key)
	return &g, nil
}

func (i *Issuer) Mint() string {
	nonce := make([]byte, 0, 1+16+32)
	nonce = append(nonce, 0x01) // version

	id := newUUIDv7(time.Now())
	nonce = append(nonce, id[:]...)

	h := hmac.New(sha256.New, i.key[:])
	h.Write([]byte("magnolia-ca.com/nonce"))
	h.Write(nonce)
	nonce = h.Sum(nonce)
	nonce = nonce[:17+16] // truncate HMAC to 128 bits

	return base64.RawURLEncoding.EncodeToString(nonce)
}

// newUUIDv7 generates a UUIDv7 without bumping the millisecond field to
// preserve monotonicity.
func newUUIDv7(t time.Time) uuid.UUID {
	var u uuid.UUID
	ms := uint64(t.UnixMilli())
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	rand.Read(u[6:])
	u[6] = (u[6] & 0x0f) | 0x70 // version 7
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return u
}

func (i *Issuer) Verify(nonce string) (uuid.UUID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return uuid.Nil(), err
	}
	if len(decoded) != 17+16 {
		return uuid.Nil(), errors.New("invalid nonce length")
	}
	if decoded[0] != 0x01 {
		return uuid.Nil(), errors.New("invalid nonce version")
	}
	h := hmac.New(sha256.New, i.key[:])
	h.Write([]byte("magnolia-ca.com/nonce"))
	h.Write(decoded[:17])
	expected := h.Sum(nil)
	if !hmac.Equal(expected[:16], decoded[17:]) {
		return uuid.Nil(), errors.New("invalid nonce HMAC")
	}
	return uuid.UUID(decoded[1:17]), nil
}

type Spent struct {
	i     *Issuer
	mu    sync.Mutex
	used  map[uuid.UUID]struct{}
	heap  []uuid.UUID
	floor uuid.UUID
	size  int
}

func NewSpent(i *Issuer, size int) *Spent {
	var f uuid.UUID
	for i := range f {
		f[i] = 0xff
	}
	boot := time.Now().UnixMilli()
	f[0] = byte(boot >> 40)
	f[1] = byte(boot >> 32)
	f[2] = byte(boot >> 24)
	f[3] = byte(boot >> 16)
	f[4] = byte(boot >> 8)
	f[5] = byte(boot)
	f[6] = (f[6] & 0x0f) | 0x70
	f[8] = (f[8] & 0x3f) | 0x80

	return &Spent{
		i:     i,
		used:  make(map[uuid.UUID]struct{}, size+1),
		heap:  make([]uuid.UUID, 0, size+1),
		floor: f,
		size:  size,
	}
}

func (s *Spent) Spend(nonce string) error {
	id, err := s.i.Verify(nonce)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if id.Compare(s.floor) <= 0 {
		return errors.New("nonce is too old")
	}
	if _, ok := s.used[id]; ok {
		return errors.New("nonce has already been spent")
	}
	s.used[id] = struct{}{}
	s.push(id)

	for len(s.used) > s.size {
		s.floor = s.pop()
		delete(s.used, s.floor)
	}
	return nil
}

func (s *Spent) push(x uuid.UUID) {
	s.heap = append(s.heap, x)
	i := len(s.heap) - 1
	for i > 0 {
		parent := (i - 1) / 2
		if s.heap[i].Compare(s.heap[parent]) >= 0 {
			break
		}
		s.heap[i], s.heap[parent] = s.heap[parent], s.heap[i]
		i = parent
	}
}

func (s *Spent) pop() uuid.UUID {
	n := len(s.heap) - 1
	min := s.heap[0]
	s.heap[0] = s.heap[n]
	s.heap = s.heap[:n]
	i := 0
	for {
		l, r := 2*i+1, 2*i+2
		smallest := i
		if l < n && s.heap[l].Compare(s.heap[smallest]) < 0 {
			smallest = l
		}
		if r < n && s.heap[r].Compare(s.heap[smallest]) < 0 {
			smallest = r
		}
		if smallest == i {
			break
		}
		s.heap[i], s.heap[smallest] = s.heap[smallest], s.heap[i]
		i = smallest
	}
	return min
}
