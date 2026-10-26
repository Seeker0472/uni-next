package generation

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
)

type Generation struct {
	ID        uint64
	Context   context.Context
	VIP       netip.Addr
	Routes    []netip.Prefix
	Interface string
}

type Gate struct {
	mu      sync.RWMutex
	current *Generation
}

func (g *Gate) Set(value Generation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	copy := value
	copy.Routes = slices.Clone(value.Routes)
	g.current = &copy
}

func (g *Gate) Clear(id uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.current != nil && g.current.ID == id {
		g.current = nil
	}
}

func (g *Gate) Acquire() (Generation, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current == nil {
		return Generation{}, errors.New("VPN is not ready")
	}
	select {
	case <-g.current.Context.Done():
		return Generation{}, errors.New("VPN generation is closing")
	default:
	}
	copy := *g.current
	copy.Routes = slices.Clone(copy.Routes)
	return copy, nil
}
