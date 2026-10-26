package session

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type KickoutBudget struct {
	mode     string
	window   time.Duration
	maximum  int
	attempts []time.Time
}

func NewKickoutBudget(mode string, window time.Duration, maximum int) *KickoutBudget {
	return &KickoutBudget{mode: mode, window: window, maximum: maximum}
}

func (b *KickoutBudget) Allow(now time.Time) bool {
	switch b.mode {
	case "stop":
		return false
	case "always":
		return true
	}
	cutoff := now.Add(-b.window)
	kept := b.attempts[:0]
	for _, attempt := range b.attempts {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	b.attempts = kept
	if len(b.attempts) >= b.maximum {
		return false
	}
	b.attempts = append(b.attempts, now)
	return true
}

type Backoff struct{ initial, maximum, current time.Duration }

func NewBackoff(initial, maximum time.Duration) *Backoff {
	return &Backoff{initial: initial, maximum: maximum}
}
func (b *Backoff) Reset() { b.current = 0 }
func (b *Backoff) Next() time.Duration {
	if b.current == 0 {
		b.current = b.initial
	} else if b.current >= b.maximum/2 {
		b.current = b.maximum
	} else {
		b.current *= 2
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return b.current
	}
	fraction := float64(binary.LittleEndian.Uint64(raw[:])) / float64(^uint64(0))
	return time.Duration(float64(b.current) * (0.8 + 0.2*fraction))
}
