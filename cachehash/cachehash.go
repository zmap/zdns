/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
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

import "container/list"

type CacheHash struct {
	h      map[interface{}]*list.Element
	l      *list.List
	len    int
	maxLen int
}

type keyValue struct {
	Key   interface{}
	Value interface{}
}

func (c *CacheHash) Init(maxLen int) {

	c.l = c.l.Init()
	c.h = make(map[interface{}]*list.Element)
	c.len = 0
	c.maxLen = maxLen
}

func (c *CacheHash) Eject() {

}

func (c *CacheHash) Add(k interface{}, v interface{}) bool {
	e, ok := c.h[k]
	if ok {
		kv := e.Value.(keyValue)
		kv.Key = k
		kv.Value = v
		c.l.MoveToFront(e)
	} else {
		if c.len >= c.maxLen {
			c.Eject()
		}
		e := make(list.Element)
		e.value = v
		c.l.
			c.len++
	}
}

func (c *CacheHash) Get(k interface{}) (interface{}, bool) {
	e, ok := c.h[k]
	if ok {
		c.l.MoveToFront(e)
		return e.Value, ok
	}
	return nil, ok
}

func (c *CacheHash) GetNoMove(k interface{}) (interface{}, bool) {
	e, ok := c.h[k]
	if ok {
		return e.Value, ok
	}
	return nil, ok
}

func (c *CacheHash) Has(k interface{}) bool {
	_, ok := c.h[k]
	return ok
}

func (c *CacheHash) Delete(k interface{}) bool {

}

func (c *CacheHash) Len() int {
	return c.len
}
