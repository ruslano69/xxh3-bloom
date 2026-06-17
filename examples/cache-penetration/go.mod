module github.com/ruslano69/xxh3-bloom/examples/cache-penetration

go 1.26.4

require (
	github.com/alicebob/miniredis/v2 v2.33.0
	github.com/redis/go-redis/v9 v9.7.0
	github.com/ruslano69/xxh3-bloom v0.6.0
)

require (
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/bits-and-blooms/bitset v1.24.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

// Use the in-repo library, not the published version, while developing.
replace github.com/ruslano69/xxh3-bloom => ../..
