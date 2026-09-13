package nonce

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"uuid"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestIssuer(t testing.TB) *Issuer {
	t.Helper()
	i, err := NewIssuer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// encode is an independent implementation of the nonce format, used to
// cross-check Mint and to build nonces around chosen UUIDs.
func encode(i *Issuer, id uuid.UUID) string {
	prefix := append([]byte{0x01}, id[:]...)
	h := hmac.New(sha256.New, i.key[:])
	h.Write([]byte("magnolia-ca.com/nonce"))
	h.Write(prefix)
	tag := h.Sum(nil)[:16]
	return base64.RawURLEncoding.EncodeToString(append(prefix, tag...))
}

// tsOf returns the 48-bit millisecond timestamp of a UUIDv7.
func tsOf(u uuid.UUID) int64 {
	return int64(u[0])<<40 | int64(u[1])<<32 | int64(u[2])<<24 |
		int64(u[3])<<16 | int64(u[4])<<8 | int64(u[5])
}

// idAt returns a UUIDv7 stamped ms with zero random bits, except for tail,
// which overwrites the last len(tail) bytes.
func idAt(ms int64, tail ...byte) uuid.UUID {
	var u uuid.UUID
	u[0], u[1], u[2], u[3], u[4], u[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	copy(u[16-len(tail):], tail)
	u[6] = (u[6] & 0x0f) | 0x70
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// bootFloor returns the floor NewSpent installs when started at ms: the
// largest UUIDv7 stamped ms.
func bootFloor(ms int64) uuid.UUID {
	f := uuid.Max()
	f[0], f[1], f[2], f[3], f[4], f[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	f[6] = 0x7f
	f[8] = 0xbf
	return f
}

func nowMilli() int64 { return time.Now().UnixMilli() }

func checkInvariants(t testing.TB, s *Spent) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.heap) != len(s.used) {
		t.Fatalf("heap has %d entries, used has %d", len(s.heap), len(s.used))
	}
	if len(s.used) > s.size {
		t.Fatalf("used has %d entries, over size %d", len(s.used), s.size)
	}
	for i := 1; i < len(s.heap); i++ {
		parent := (i - 1) / 2
		if s.heap[parent].Compare(s.heap[i]) > 0 {
			t.Fatalf("heap violation at %d: %v > %v", i, s.heap[parent], s.heap[i])
		}
	}
	for _, u := range s.heap {
		if _, ok := s.used[u]; !ok {
			t.Fatalf("heap entry %v is not in used", u)
		}
		if u.Compare(s.floor) <= 0 {
			t.Fatalf("tracked nonce %v is at or below floor %v", u, s.floor)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	if _, err := NewIssuer(testKey[:31]); err == nil {
		t.Error("NewIssuer accepted a 31-byte key")
	}

	synctest.Test(t, func(t *testing.T) {
		i := newTestIssuer(t)
		n := i.Mint()
		if len(n) != 44 {
			t.Errorf("nonce is %d characters, want 44", len(n))
		}
		raw, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil || len(raw) != 33 || raw[0] != 0x01 {
			t.Fatalf("nonce decodes to %x (%v)", raw, err)
		}
		id, err := i.Verify(n)
		if err != nil {
			t.Fatal(err)
		}
		if id != uuid.UUID(raw[1:17]) {
			t.Errorf("Verify returned %v, nonce carries %x", id, raw[1:17])
		}
		if id[6]>>4 != 7 || id[8]>>6 != 2 {
			t.Errorf("uuid %v does not have version 7 and variant 10", id)
		}
		if ts := tsOf(id); ts != nowMilli() {
			t.Errorf("timestamp %d, want %d", ts, nowMilli())
		}
		if got := encode(i, id); got != n {
			t.Errorf("Mint produced %s, independent encoder produces %s", n, got)
		}
		if i.Mint() == n {
			t.Error("two Mint calls returned the same nonce")
		}

		other, err := NewIssuer([]byte("fedcba9876543210fedcba9876543210"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Verify(n); err == nil {
			t.Error("nonce verified under a different key")
		}
	})
}

func TestVerifyRejects(t *testing.T) {
	i := newTestIssuer(t)
	n := encode(i, idAt(nowMilli(), 0xab, 0xcd))
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString

	reject := func(name, nonce string) {
		t.Helper()
		if _, err := i.Verify(nonce); err == nil {
			t.Errorf("%s: Verify accepted %q", name, nonce)
		}
	}
	reject("empty", "")
	reject("padded", n+"=")
	reject("garbage", "!!!!")
	reject("short", enc(raw[:32]))
	reject("long", enc(append(raw[:33:33], 0)))
	reject("full HMAC", enc(append(raw[:33:33], raw[17:33]...)))

	for _, v := range []byte{0x00, 0x02, 0x81} {
		reject("version", enc(append([]byte{v}, raw[1:]...)))
	}

	for pos := range raw {
		for bit := range 8 {
			tampered := append([]byte(nil), raw...)
			tampered[pos] ^= 1 << bit
			reject("bit flip", enc(tampered))
		}
	}

	if _, err := i.Verify(n); err != nil {
		t.Errorf("original nonce no longer verifies: %v", err)
	}
}

func TestUUIDv7Order(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		a, b := r.Int64N(1<<48), r.Int64N(1<<48)
		if r.IntN(4) == 0 {
			b = a
		}
		ua := newUUIDv7(time.UnixMilli(a).Add(time.Duration(r.IntN(1000)) * time.Microsecond))
		ub := newUUIDv7(time.UnixMilli(b).Add(time.Duration(r.IntN(1000)) * time.Microsecond))
		if tsOf(ua) != a || tsOf(ub) != b {
			t.Fatalf("timestamp of %v = %d, want %d; timestamp of %v = %d, want %d",
				ua, tsOf(ua), a, ub, tsOf(ub), b)
		}
		if ua[6]>>4 != 7 || ua[8]>>6 != 2 {
			t.Fatalf("%v does not have version 7 and variant 10", ua)
		}
		switch cmp := ua.Compare(ub); {
		case a < b && cmp >= 0, a > b && cmp <= 0:
			t.Fatalf("%v (ts %d) compares %d to %v (ts %d)", ua, a, cmp, ub, b)
		}
	}
}

func TestBootFloor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		i := newTestIssuer(t)
		s := NewSpent(i, 10)
		boot := nowMilli()

		if s.floor != bootFloor(boot) {
			t.Fatalf("boot floor is %v, want %v", s.floor, bootFloor(boot))
		}
		if err := s.Spend(i.Mint()); err == nil {
			t.Error("nonce stamped in the boot millisecond accepted")
		}
		if err := s.Spend(encode(i, idAt(boot, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))); err == nil {
			t.Error("largest nonce of the boot millisecond accepted")
		}
		if err := s.Spend(encode(i, idAt(boot+1))); err != nil {
			t.Errorf("smallest nonce of the next millisecond rejected: %v", err)
		}

		time.Sleep(time.Millisecond)
		if err := s.Spend(i.Mint()); err != nil {
			t.Errorf("nonce minted after the boot millisecond rejected: %v", err)
		}
		checkInvariants(t, s)
	})
}

func TestDoubleSpend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		i := newTestIssuer(t)
		s := NewSpent(i, 10)
		time.Sleep(time.Millisecond)

		n := i.Mint()
		if err := s.Spend(n); err != nil {
			t.Fatal(err)
		}
		if err := s.Spend(n); err == nil {
			t.Error("second Spend succeeded")
		}
		if err := s.Spend(n); err == nil {
			t.Error("third Spend succeeded")
		}

		if err := s.Spend(n[:43] + "A"); err == nil {
			t.Error("tampered nonce accepted")
		}
		if len(s.used) != 1 {
			t.Errorf("used has %d entries after one valid spend", len(s.used))
		}
		checkInvariants(t, s)
	})
}

func TestSameMillisecondSiblings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		i := newTestIssuer(t)
		s := NewSpent(i, 1)
		time.Sleep(time.Millisecond)
		ms := nowMilli()

		a, b, c := idAt(ms, 1), idAt(ms, 2), idAt(ms, 3)
		d := idAt(ms + 1)
		if a.Compare(b) >= 0 || b.Compare(c) >= 0 || c.Compare(d) >= 0 {
			t.Fatal("test ids are not in increasing order")
		}

		if err := s.Spend(encode(i, b)); err != nil {
			t.Fatal(err)
		}
		if err := s.Spend(encode(i, d)); err != nil {
			t.Fatal(err)
		}
		if s.floor != b {
			t.Fatalf("floor is %v, want %v", s.floor, b)
		}
		if _, ok := s.used[b]; ok {
			t.Fatal("evicted nonce still in used")
		}

		if err := s.Spend(encode(i, a)); err == nil {
			t.Error("smaller sibling accepted after floor moved past it")
		}
		if err := s.Spend(encode(i, b)); err == nil {
			t.Error("evicted nonce accepted again")
		}
		if err := s.Spend(encode(i, c)); err != nil {
			t.Errorf("larger sibling rejected: %v", err)
		}
		checkInvariants(t, s)
	})
}

func TestCrossRestartReplay(t *testing.T) {
	for _, restartDelay := range []time.Duration{0, time.Millisecond, time.Hour} {
		t.Run(restartDelay.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				i := newTestIssuer(t)
				s1 := NewSpent(i, 8)
				rnd := rand.New(rand.NewPCG(3, 4))

				var accepted []string
				for range 200 {
					if rnd.IntN(2) == 0 {
						time.Sleep(time.Millisecond)
					}
					n := i.Mint()
					if err := s1.Spend(n); err == nil {
						accepted = append(accepted, n)
					}
				}
				if len(accepted) < 150 {
					t.Fatalf("only %d of 200 spends accepted", len(accepted))
				}
				checkInvariants(t, s1)

				time.Sleep(restartDelay)
				s2 := NewSpent(i, 8)
				for _, n := range accepted {
					if err := s2.Spend(n); err == nil {
						t.Errorf("nonce %s spent before restart accepted after it", n)
					}
				}
				if len(s2.used) != 0 {
					t.Errorf("used has %d entries after replay attempts", len(s2.used))
				}

				time.Sleep(time.Millisecond)
				if err := s2.Spend(i.Mint()); err != nil {
					t.Errorf("fresh nonce rejected after restart: %v", err)
				}
				checkInvariants(t, s2)
			})
		})
	}
}

func TestCapEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 100
		i := newTestIssuer(t)
		s := NewSpent(i, size)
		boot := s.floor

		var nonces []string
		var ids []uuid.UUID
		spend := func() {
			t.Helper()
			time.Sleep(time.Millisecond)
			n := i.Mint()
			id, err := i.Verify(n)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Spend(n); err != nil {
				t.Fatal(err)
			}
			nonces = append(nonces, n)
			ids = append(ids, id)
			checkInvariants(t, s)
		}

		for range size {
			spend()
		}
		if s.floor != boot {
			t.Errorf("floor moved before the cap was exceeded")
		}
		if len(s.used) != size || len(s.heap) != size {
			t.Errorf("used has %d entries and heap %d, want %d", len(s.used), len(s.heap), size)
		}

		spend()
		if len(s.used) != size || len(s.heap) != size {
			t.Errorf("used has %d entries and heap %d after eviction, want %d", len(s.used), len(s.heap), size)
		}
		if s.floor != ids[0] {
			t.Errorf("floor is %v, want oldest entry %v", s.floor, ids[0])
		}
		if _, ok := s.used[ids[0]]; ok {
			t.Error("oldest entry still in used")
		}
		if _, ok := s.used[ids[1]]; !ok {
			t.Error("second oldest entry evicted early")
		}
		if err := s.Spend(nonces[0]); err == nil {
			t.Error("evicted nonce accepted")
		}

		for range 50 {
			spend()
		}
		if s.floor != ids[50] {
			t.Errorf("floor is %v, want %v", s.floor, ids[50])
		}
		for k, id := range ids {
			_, ok := s.used[id]
			if want := k > 50; ok != want {
				t.Errorf("ids[%d] in used = %v, want %v", k, ok, want)
			}
			if err := s.Spend(nonces[k]); err == nil {
				t.Errorf("nonces[%d] accepted twice", k)
			}
		}
	})
}

func TestFloorMonotonic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 16
		i := newTestIssuer(t)
		s := NewSpent(i, size)
		rnd := rand.New(rand.NewPCG(5, 6))

		var accepted []string
		prevFloor := s.floor
		for step := range 5000 {
			if rnd.IntN(3) == 0 {
				time.Sleep(time.Duration(rnd.IntN(3)) * time.Millisecond)
			}

			var n string
			switch rnd.IntN(3) {
			case 0:
				n = i.Mint()
			case 1:
				// Anywhere from well below the floor to well ahead of it.
				ms := nowMilli() + int64(rnd.IntN(900)) - 800
				var tail [10]byte
				for k := range tail {
					tail[k] = byte(rnd.IntN(256))
				}
				n = encode(i, idAt(ms, tail[:]...))
			case 2:
				if len(accepted) == 0 {
					continue
				}
				n = accepted[rnd.IntN(len(accepted))]
			}

			err := s.Spend(n)
			if s.floor.Compare(prevFloor) < 0 {
				t.Fatalf("step %d: floor decreased from %v to %v", step, prevFloor, s.floor)
			}
			prevFloor = s.floor
			checkInvariants(t, s)
			if err == nil {
				accepted = append(accepted, n)
			}

			if step%250 == 0 {
				for _, n := range accepted {
					if err := s.Spend(n); err == nil {
						t.Fatalf("step %d: previously accepted nonce %s accepted again", step, n)
					}
				}
			}
		}
		if len(accepted) < 1000 {
			t.Errorf("only %d spends accepted", len(accepted))
		}
	})
}

func TestConcurrentSpend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		i := newTestIssuer(t)
		s := NewSpent(i, 1000)
		time.Sleep(time.Millisecond)

		for range 50 {
			n := i.Mint()
			var successes atomic.Int32
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					if err := s.Spend(n); err == nil {
						successes.Add(1)
					}
				})
			}
			wg.Wait()
			if got := successes.Load(); got != 1 {
				t.Errorf("%d successful spends of the same nonce", got)
			}
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 100 {
					if err := s.Spend(i.Mint()); err != nil {
						t.Error(err)
					}
				}
			})
		}
		wg.Wait()
		checkInvariants(t, s)
	})
}

func FuzzVerify(f *testing.F) {
	i := newTestIssuer(f)
	s := NewSpent(i, 10)

	f.Add(encode(i, idAt(nowMilli()+1)))
	f.Add(encode(i, idAt(nowMilli()+5000)))
	f.Add(encode(i, idAt(0)))
	f.Add("")
	f.Add(strings.Repeat("A", 44))
	f.Add(strings.Repeat("_", 44))

	f.Fuzz(func(t *testing.T, nonce string) {
		id, err := i.Verify(nonce)
		s.Spend(nonce)
		if err != nil {
			return
		}
		// The base64 decoder skips newlines; otherwise, the encoding is
		// canonical.
		canonical := strings.NewReplacer("\r", "", "\n", "").Replace(nonce)
		if got := encode(i, id); got != canonical {
			t.Errorf("valid nonce %q re-encodes as %q", nonce, got)
		}
	})
}
