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
	"container/list"
	"sync"

	log "github.com/sirupsen/logrus"
)

// CacheHash is an LRU cache implemented with a hash map and a doubly linked list. The list stores key-value pairs
// in the order they were accessed, with the most recently accessed key-value pair at the front of the list.
// This allows for O(1) insertions, deletions, and lookups and ensures the most recently accesssed elements are
// persisted in the cache.
type CacheHash struct {
	sync.Mutex
	h       map[interface{}]*list.Element
	l       *list.List
	len     int
	maxLen  int
	ejectCB func(interface{}, interface{})
}

type keyValue struct {
	Key   interface{}
	Value interface{}
}

// Init initializes the cache with a maximum length.
func (c *CacheHash) Init(maxLen int) {
	c.l = list.New()
	c.l = c.l.Init()
	c.h = make(map[interface{}]*list.Element)
	c.len = 0
	c.maxLen = maxLen
}

// Eject removes the least-recently used key-value pair from the cache.
func (c *CacheHash) Eject() {
	if c.len == 0 {
		// nothing to eject
		return
	}
	e := c.l.Back()
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: Eject: invalid list element value type")
	}
	if c.ejectCB != nil {
		c.ejectCB(kv.Key, kv.Value)
	}
	delete(c.h, kv.Key)
	c.l.Remove(e)
	c.len--
}

// Upsert upserts a new key-value pair into the cache.
// If the key already exists, the value is updated and the key is moved to the front of the list.
// If the key does not exist in the cache, the key-value pair is added to the front of the list.
// Returns whether the key already existed in the cache.
func (c *CacheHash) Upsert(k interface{}, v interface{}) bool {
	var updatedKV keyValue
	updatedKV.Key = k
	updatedKV.Value = v
	e, ok := c.h[k]
	if ok {
		// update value to have the new value
		e.Value = updatedKV
		c.l.MoveToFront(e)
		return true
	}
	if c.len >= c.maxLen {
		// cache is full, remove oldest key-value pair
		c.Eject()
	}
	e = c.l.PushFront(updatedKV)
	c.len++
	c.h[k] = e
	return false
}

// First returns the key-value pair at the front of the list.
// Returns nil, nil if the cache is empty.
func (c *CacheHash) First() (k interface{}, v interface{}) {
	if c.len == 0 {
		return nil, nil
	}
	e := c.l.Front()
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: First: invalid list element value type")
	}
	return kv.Key, kv.Value
}

// Last returns the key-value pair at the back of the list.
// Returns nil, nil if the cache is empty.
func (c *CacheHash) Last() (k interface{}, v interface{}) {
	if c.len == 0 {
		return nil, nil
	}
	e := c.l.Back()
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: Last: invalid list element value type")
	}
	return kv.Key, kv.Value
}

// Get returns the value associated with the key and whether the key was found in the cache.
// It also moves it to the front of the list.
// v is nil if the key was not found.
func (c *CacheHash) Get(k interface{}) (v interface{}, found bool) {
	e, ok := c.h[k]
	if !ok {
		return nil, false
	}
	c.l.MoveToFront(e)
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: Get: invalid list element value type")
	}
	return kv.Value, true
}

// GetNoMove returns the value associated with the key and whether the key was found in the cache.
func (c *CacheHash) GetNoMove(k interface{}) (v interface{}, found bool) {
	e, ok := c.h[k]
	if !ok {
		return nil, false
	}
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: GetNoMove: invalid list element value type")
	}
	return kv.Value, true
}

// Has returns whether the key is in the cache.
func (c *CacheHash) Has(k interface{}) bool {
	_, ok := c.h[k]
	return ok
}

// Delete removes the key-value pair from the cache and returns the value and whether the key was found.
// v is nil if the key was not found.
func (c *CacheHash) Delete(k interface{}) (v interface{}, found bool) {
	e, ok := c.h[k]
	if !ok {
		return nil, false
	}
	kv, ok := e.Value.(keyValue)
	if !ok {
		log.Panic("CacheHash: Delete: invalid list element value type")
	}
	delete(c.h, k)
	c.l.Remove(e)
	c.len--
	return kv.Value, true
}

// Len returns the number of key-value pairs in the cache.
func (c *CacheHash) Len() int {
	return c.len
}

// RegisterCB registers a callback function to be called when an element is ejected from the cache.
func (c *CacheHash) RegisterCB(newCB func(interface{}, interface{})) {
	c.ejectCB = newCB
}
