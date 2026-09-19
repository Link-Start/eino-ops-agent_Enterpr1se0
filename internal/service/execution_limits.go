package service

import (
	"context"
	"sort"
)

func (s *Service) acquire(ctx context.Context, hostIDs ...string) (func(), error) {
	uniqueHostIDs := make([]string, 0, len(hostIDs))
	seen := make(map[string]struct{}, len(hostIDs))
	for _, hostID := range hostIDs {
		if _, exists := seen[hostID]; hostID == "" || exists {
			continue
		}
		seen[hostID] = struct{}{}
		uniqueHostIDs = append(uniqueHostIDs, hostID)
	}
	sort.Strings(uniqueHostIDs)
	s.semMu.Lock()
	hostSems := make([]chan struct{}, 0, len(uniqueHostIDs))
	for _, hostID := range uniqueHostIDs {
		hostSem := s.hostSems[hostID]
		if hostSem == nil {
			limit := s.limits.HostConcurrency
			if limit <= 0 {
				limit = 2
			}
			hostSem = make(chan struct{}, limit)
			s.hostSems[hostID] = hostSem
		}
		hostSems = append(hostSems, hostSem)
	}
	s.semMu.Unlock()
	select {
	case s.globalSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	acquired := make([]chan struct{}, 0, len(hostSems))
	for _, hostSem := range hostSems {
		select {
		case hostSem <- struct{}{}:
			acquired = append(acquired, hostSem)
		case <-ctx.Done():
			for index := len(acquired) - 1; index >= 0; index-- {
				<-acquired[index]
			}
			<-s.globalSem
			return nil, ctx.Err()
		}
	}
	return func() {
		for index := len(acquired) - 1; index >= 0; index-- {
			<-acquired[index]
		}
		<-s.globalSem
	}, nil
}
