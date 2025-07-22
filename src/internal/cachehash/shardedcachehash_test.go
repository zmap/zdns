package cachehash

import "testing"

func FuzzGetShardID(f *testing.F) {
	cache := &ShardedCacheHash{}
	cache.Init(1000, 4096) // Set a known non-zero shardLen

	// Add a few seed inputs
	f.Add("hello")
	f.Add("world")
	f.Add("hello my name is cachehash and I am a sharded cache")

	f.Fuzz(func(t *testing.T, k string) {
		// Recover from panics caused by nil or bad formats
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with input %v: %v", k, r)
			}
		}()
		shardID := cache.getShardID(k)
		if shardID < 0 || shardID >= cache.shardsLen {
			t.Errorf("shardID out of range: got %d, want 0 <= id < %d (input=%v)", shardID, cache.shardsLen, k)
		}
	})
}
