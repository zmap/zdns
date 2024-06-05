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

	"github.com/stretchr/testify/assert"
)

func TestAddOne(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Upsert("key1", "value1")
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
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
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
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
	ch.Upsert("key3", "value3")
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
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
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
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
	ch.Upsert("key3", "value3")
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

func TestUpsertExistingBumpsToFront(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
	ch.Upsert("key3", "value3")
	ch.Upsert("key1", "newValue1")
	k, v := ch.First()
	assert.Equal(t, "key1", k, "key1 should be bumped to front since it was just added")
	assert.Equal(t, "newValue1", v, "add existing should update value")

	k, v = ch.Last()
	assert.Equal(t, "key2", k, "key2 should be last")
	assert.Equal(t, "value2", v, "key2 should have value: value2")
}

func TestUpsertWithFullCache(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(2)
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")

	k, v := ch.First()
	assert.Equal(t, "key2", k, "First key should be key2")
	assert.Equal(t, "value2", v, "First value should be value2")

	k, v = ch.Last()
	assert.Equal(t, "key1", k, "Last key should be key1")
	assert.Equal(t, "value1", v, "Last value should be value1")

	ch.Upsert("key3", "value3")

	assert.Len(t, ch.h, 2, "Cache should have 2 elements, since it is full and one was evicted")

	k, v = ch.First()
	assert.Equal(t, "key3", k, "First key should be key3")
	assert.Equal(t, "value3", v, "First value should be value3")

	// key1 should have been evicted since it was the oldest, and key2 should still be in the cache
	k, v = ch.Last()
	assert.Equal(t, "key2", k, "Last key should be key2")
	assert.Equal(t, "value2", v, "Last value should be value2")
}

func TestGetNoMove(t *testing.T) {
	ch := new(CacheHash)
	ch.Init(5)
	ch.Upsert("key1", "value1")
	ch.Upsert("key2", "value2")
	ch.GetNoMove("key1")

	k, v := ch.First()
	assert.Equal(t, "key2", k, "First key should be key2")
	assert.Equal(t, "value2", v, "First value should be value2")

	v, found := ch.GetNoMove("key1")
	assert.True(t, found, "key1 should be found")
	assert.Equal(t, "value1", v, "value1 should be returned")

	k, v = ch.First()
	assert.Equal(t, "key2", k, "First key should still be key2 post GetNoMove")
	assert.Equal(t, "value2", v, "First value should be value2")
}
