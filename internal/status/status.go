// Package status publishes a secret-free, read-only process snapshot.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Snapshot struct {
	PID            int       `json:"pid"`
	StartedAt      time.Time `json:"started_at"`
	ProcessStart   string    `json:"process_start"`
	UpdatedAt      time.Time `json:"updated_at"`
	Phase          string    `json:"phase"`
	Mode           string    `json:"mode"`
	Generation     uint64    `json:"generation"`
	VIP            string    `json:"vip,omitempty"`
	Routes         []string  `json:"routes,omitempty"`
	SocksReady     bool      `json:"socks_ready"`
	HTTPReady      bool      `json:"http_ready"`
	LastHeartbeat  time.Time `json:"last_heartbeat,omitempty"`
	Reconnects     uint64    `json:"reconnects"`
	LastErrorCode  string    `json:"last_error_code,omitempty"`
	LastErrorStage string    `json:"last_error_stage,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	snapshot Snapshot
	initErr  error
}

func NewStore(runDir string) *Store {
	now := time.Now().UTC()
	identity, identityErr := processIdentity(os.Getpid())
	return &Store{
		path:     filepath.Join(runDir, "status.json"),
		snapshot: Snapshot{PID: os.Getpid(), ProcessStart: identity, StartedAt: now, UpdatedAt: now, Phase: "idle"},
		initErr:  identityErr,
	}
}

func (s *Store) Update(fn func(*Snapshot)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initErr != nil {
		return s.initErr
	}
	fn(&s.snapshot)
	s.snapshot.UpdatedAt = time.Now().UTC()
	s.snapshot.Routes = slices.Clone(s.snapshot.Routes)
	return writeAtomic(s.path, s.snapshot)
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := s.snapshot
	copy.Routes = slices.Clone(copy.Routes)
	return copy
}

func Read(runDir string) (Snapshot, error) {
	data, err := os.ReadFile(filepath.Join(runDir, "status.json"))
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode status: %w", err)
	}
	if snapshot.PID <= 0 || snapshot.ProcessStart == "" {
		return Snapshot{}, errors.New("status has invalid process identity")
	}
	identity, err := processIdentity(snapshot.PID)
	if err != nil {
		return snapshot, fmt.Errorf("stale status: %w", err)
	}
	if identity != snapshot.ProcessStart {
		return snapshot, errors.New("stale status: process identity does not match")
	}
	return snapshot, nil
}

func writeAtomic(path string, value Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
