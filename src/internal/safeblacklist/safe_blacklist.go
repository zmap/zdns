/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package safeblacklist

import (
	"sync"

	"github.com/zmap/go-iptree/blacklist"
)

// SafeBlacklist is a thread-safe wrapper around the blacklist package
type SafeBlacklist struct {
	Blacklist *blacklist.Blacklist
	lock      *sync.RWMutex
}

func New() *SafeBlacklist {
	return &SafeBlacklist{
		Blacklist: blacklist.New(),
		lock:      &sync.RWMutex{},
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
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.Blacklist.IsBlacklisted(ip)
}
