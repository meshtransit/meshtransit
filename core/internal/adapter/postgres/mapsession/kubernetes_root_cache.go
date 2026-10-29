package mapsession

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

// maximumKubernetesRootCacheBytes bounds the DER the root cache holds for
// every Network together: about 60,000 roots (K1a4d design §3.3).
const maximumKubernetesRootCacheBytes = 32 << 20

// kubernetesRootCache holds clusters' roots' DER by fingerprint, least
// recently used first out, bounded by bytes. DER never changes for a
// fingerprint, so an entry is never stale; it is checked against its
// fingerprint before it is kept. The DER slices are shared, never written.
type kubernetesRootCache struct {
	mu       sync.Mutex
	limit    int
	size     int
	order    *list.List // of [32]byte, most recent at the front
	elements map[[32]byte]*list.Element
	roots    map[[32]byte][]byte
}

func newKubernetesRootCache(limit int) *kubernetesRootCache {
	return &kubernetesRootCache{
		limit: limit, order: list.New(), elements: map[[32]byte]*list.Element{}, roots: map[[32]byte][]byte{},
	}
}

// get returns a root's DER and marks it used.
func (cache *kubernetesRootCache) get(fingerprint [32]byte) ([]byte, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element, ok := cache.elements[fingerprint]
	if !ok {
		return nil, false
	}
	cache.order.MoveToFront(element)
	return cache.roots[fingerprint], true
}

// put keeps a root's DER when it is its fingerprint's and fits; it reports
// whether it was kept. One held already is only marked used, unhashed.
func (cache *kubernetesRootCache) put(fingerprint [32]byte, der []byte) bool {
	if cache.touch(fingerprint) {
		return true
	}
	if len(der) == 0 || len(der) > cache.limit || sha256.Sum256(der) != fingerprint {
		return false
	}
	return cache.keep(fingerprint, der)
}

// touch marks a held root used and reports whether it is held.
func (cache *kubernetesRootCache) touch(fingerprint [32]byte) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element, ok := cache.elements[fingerprint]
	if ok {
		cache.order.MoveToFront(element)
	}
	return ok
}

// keep holds DER already checked against its fingerprint (an inventory's,
// which NewKubernetesTrust checked); it reports whether it fits.
func (cache *kubernetesRootCache) keep(fingerprint [32]byte, der []byte) bool {
	if len(der) == 0 || len(der) > cache.limit {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if element, ok := cache.elements[fingerprint]; ok {
		cache.order.MoveToFront(element)
		return true
	}
	for cache.size+len(der) > cache.limit {
		oldest := cache.order.Back()
		evicted, _ := oldest.Value.([32]byte)
		cache.order.Remove(oldest)
		cache.size -= len(cache.roots[evicted])
		delete(cache.elements, evicted)
		delete(cache.roots, evicted)
	}
	cache.elements[fingerprint] = cache.order.PushFront(fingerprint)
	cache.roots[fingerprint] = der
	cache.size += len(der)
	return true
}
