// Demonstrates defending a Redis-backed service against a cache-penetration
// attack (a flood of queries for keys that do not exist, designed to slip past
// the cache and hammer the expensive backend) using an in-process Bloom filter.
//
// Everything runs in-process against an embedded miniredis — no Docker, no
// network, no external server. The "attack" only ever touches localhost.
//
//	go run .
//
// Because the attacker chooses the keys, this is the public/untrusted trust
// boundary, so the guard uses bloom.Secured (seeded + SipHash). An unseeded
// filter could be defeated by precomputed false-positive keys.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	bloom "github.com/ruslano69/xxh3-bloom"
)

const (
	realKeys = 100_000   // legitimate keyspace
	flood    = 500_000   // attack volume (non-existent keys)
	fpTarget = 0.001     // 0.1% false-positive budget
)

func realKey(i int) string  { return fmt.Sprintf("user:%d:profile", i) }
func ghostKey(i int) string { return fmt.Sprintf("ghost:%d:profile", i) } // never exists

func main() {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	// Build the legitimate keyspace: populate the cache and the guard together.
	guard := bloom.NewBlockedTuned(realKeys, fpTarget, bloom.Secured(bloom.RandomSeed()))
	for i := 0; i < realKeys; i++ {
		k := realKey(i)
		rdb.Set(ctx, k, "1", 0)
		guard.Add([]byte(k))
	}

	fmt.Println("=== Cache-penetration defense (embedded miniredis) ===")
	fmt.Printf("Legit keys : %d\n", realKeys)
	fmt.Printf("Attack flood: %d non-existent keys\n", flood)
	fmt.Printf("Guard      : Blocked-Tuned, fp=%.3f, %s (seeded)\n\n", fpTarget, guard.Hash())

	// A backend lookup is the expensive resource we are protecting. We just
	// count how often the flood reaches it.
	noGuard := attack(ctx, rdb, nil)
	withGuard := attack(ctx, rdb, guard)

	report("WITHOUT guard", noGuard)
	report("WITH guard   ", withGuard)

	fmt.Printf("\nBackend hits cut: %d -> %d  (%.1f%% of the flood blocked before it left the process)\n",
		noGuard.backendHits, withGuard.backendHits,
		100*float64(noGuard.backendHits-withGuard.backendHits)/float64(noGuard.backendHits))

	// Sanity: legitimate traffic still passes (no false negatives).
	missed := 0
	for i := 0; i < realKeys; i++ {
		if !guard.Test([]byte(realKey(i))) {
			missed++
		}
	}
	fmt.Printf("Legit keys wrongly blocked: %d (must be 0 — Bloom has no false negatives)\n", missed)
}

type result struct {
	redisGets   int
	backendHits int
	dur         time.Duration
}

// attack replays the flood. If guard != nil, each key is checked against it
// first and rejected on a negative — never touching Redis or the backend.
func attack(ctx context.Context, rdb *redis.Client, guard *bloom.BlockedFilter) result {
	var r result
	start := time.Now()
	for i := 0; i < flood; i++ {
		k := ghostKey(i)

		if guard != nil && !guard.Test([]byte(k)) {
			continue // definitely absent: 404 without any I/O
		}

		// Cache lookup. A miss falls through to the backend.
		r.redisGets++
		if _, err := rdb.Get(ctx, k).Result(); err == redis.Nil {
			r.backendHits++ // the expensive path the attacker wants to trigger
		}
	}
	r.dur = time.Since(start)
	return r
}

func report(label string, r result) {
	fmt.Printf("%s: redis GETs=%-7d backend hits=%-7d time=%s\n",
		label, r.redisGets, r.backendHits, r.dur.Round(time.Millisecond))
}
