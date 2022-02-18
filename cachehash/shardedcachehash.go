/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

package cachehash

import (
	"fmt"
	"hash/crc32"
)

type ShardedCacheHash struct {
	shards    []CacheHash
	shardsLen int
}

func (c *ShardedCacheHash) Init(maxLen int, shards int) {
	c.shardsLen = shards
	shardLen := maxLen / shards
	c.shards = make([]CacheHash, shards)
	for i := 0; i < shards; i++ {
		c.shards[i].Init(shardLen)
	}
}

func (c *ShardedCacheHash) getShardID(k interface{}) int {
	kb := []byte(fmt.Sprintf("%v", k))
	return int(crc32.ChecksumIEEE(kb)) % c.shardsLen
}

func (c *ShardedCacheHash) getShard(k interface{}) *CacheHash {
	return &c.shards[c.getShardID(k)]
}

func (c *ShardedCacheHash) Add(k interface{}, v interface{}) bool {
	return c.getShard(k).Add(k, v)
}

func (c *ShardedCacheHash) Get(k interface{}) (interface{}, bool) {
	return c.getShard(k).Get(k)
}

func (c *ShardedCacheHash) GetNoMove(k interface{}) (interface{}, bool) {
	return c.getShard(k).GetNoMove(k)
}

func (c *ShardedCacheHash) Has(k interface{}) bool {
	return c.getShard(k).Has(k)
}

func (c *ShardedCacheHash) Delete(k interface{}) (interface{}, bool) {
	return c.getShard(k).Delete(k)
}

func (c *ShardedCacheHash) RegisterCB(newCB func(interface{}, interface{})) {
	for i := 0; i < c.shardsLen; i++ {
		c.shards[i].RegisterCB(newCB)
	}
}

func (c *ShardedCacheHash) Lock(k interface{}) {
	c.getShard(k).Lock()
}

func (c *ShardedCacheHash) Unlock(k interface{}) {
	c.getShard(k).Unlock()
}
