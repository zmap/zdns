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
	"testing"
)

func TestAddOne(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Add("key1", "value1")
	if ch.Len() != 1 {
		t.Error("unable to add any elements")
	}
	if k, v := ch.First(); k != "key1" || v != "value1" {
		t.Error("first and last not set on add")
	}
	fmt.Println(ch.Get("key1"))
	if v, ok := ch.Get("key1"); ok != true || v != "value1" {
		t.Error("Get does not retrieve value")
	}
}

func TestFirstLastSetProperly(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Add("key1", "value1")
	ch.Add("key2", "value2")
	if ch.Len() != 2 {
		t.Error("unable to add multiple elements")
	}
	if k, v := ch.First(); k != "key2" || v != "value2" {
		t.Error("first and last not set on add")
	}
	if k, v := ch.Last(); k != "key1" || v != "value1" {
		t.Error("first and last not set on add")
	}
}

func TestDelete(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Add("key1", "value1")
	ch.Add("key2", "value2")
	ch.Add("key3", "value3")
	if ch.Len() != 3 {
		t.Error("unable to add multiple elements")
	}
	if v, ok := ch.Delete("key1"); ok != true || v != "value1" {
		t.Error("delete not successful when element exists")
	}
	if ch.Len() != 2 {
		t.Error("delete doesn't update number of elements")
	}
	if v, ok := ch.Delete("key1"); ok != false || v != nil {
		t.Error("delete does not fail when element does not exist")
	}
	if ch.Len() != 2 {
		t.Error("delete changes number of elements when elements does not exist")
	}
	if k, v := ch.First(); k != "key3" || v != "value3" {
		t.Error("something awry with delete")
	}
	if k, v := ch.Last(); k != "key2" || v != "value2" {
		t.Error("something awry with delete")
	}
}

func TestMoveFront(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Add("key1", "value1")
	ch.Add("key2", "value2")
	ch.Get("key1")
	if k, v := ch.First(); k != "key1" || v != "value1" {
		t.Error("first and last not set on add")
	}
	if k, v := ch.Last(); k != "key2" || v != "value2" {
		t.Error("first and last not set on add")
	}
}

func TestEject(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(2)
	ch.Add("key1", "value1")
	ch.Add("key2", "value2")
	ch.Add("key3", "value3")
	if ch.Len() != 2 {
		t.Error("length not respected")
	}
	if k, v := ch.Last(); k != "key2" || v != "value2" {
		t.Error("first and last not set on add")
	}
	if k, v := ch.First(); k != "key3" || v != "value3" {
		t.Error("first and last not set on add")
	}
	if v, ok := ch.Get("key1"); ok != false || v != nil {
		t.Error("Ejected element not removed from hash")
	}
}
