package safe_blacklist

import (
	"github.com/zmap/go-iptree/blacklist"
	"sync"
)

// SafeBlacklist is a thread-safe wrapper around the blacklist package
type SafeBlacklist struct {
	Blacklist *blacklist.Blacklist
	lock      *sync.Mutex
}

func New() *SafeBlacklist {
	return &SafeBlacklist{
		Blacklist: blacklist.New(),
		lock:      &sync.Mutex{},
	}
}

func (b *SafeBlacklist) AddEntry(cidr string) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.Blacklist.AddEntry(cidr)
}

func (b *SafeBlacklist) ParseFromFile(path string) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.Blacklist.ParseFromFile(path)
}

func (b *SafeBlacklist) IsBlacklisted(ip string) (bool, error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.Blacklist.IsBlacklisted(ip)
}
