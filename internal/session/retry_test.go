package session

import (
	"testing"
	"time"
)

func TestBoundedKickoutBudgetUsesSlidingWindow(t *testing.T) {
	budget := NewKickoutBudget("bounded", 10*time.Minute, 3)
	now := time.Now()
	for index := range 3 {
		if !budget.Allow(now.Add(time.Duration(index) * time.Minute)) {
			t.Fatalf("attempt %d unexpectedly rejected", index)
		}
	}
	if budget.Allow(now.Add(3 * time.Minute)) {
		t.Fatal("fourth attempt in window must be rejected")
	}
	if !budget.Allow(now.Add(11 * time.Minute)) {
		t.Fatal("expired attempt should release budget")
	}
}

func TestKickoutModes(t *testing.T) {
	if NewKickoutBudget("stop", time.Minute, 3).Allow(time.Now()) {
		t.Fatal("stop mode allowed retry")
	}
	always := NewKickoutBudget("always", time.Minute, 0)
	for range 100 {
		if !always.Allow(time.Now()) {
			t.Fatal("always mode rejected retry")
		}
	}
}

func TestBackoffBoundsAndReset(t *testing.T) {
	backoff := NewBackoff(time.Second, 4*time.Second)
	for index, maximum := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		value := backoff.Next()
		if value < maximum*8/10 || value > maximum {
			t.Fatalf("step %d outside bounds: %s", index, value)
		}
	}
	backoff.Reset()
	value := backoff.Next()
	if value < 800*time.Millisecond || value > time.Second {
		t.Fatalf("reset backoff=%s", value)
	}
}
