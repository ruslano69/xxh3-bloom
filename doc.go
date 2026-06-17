/*
Package bloom implements Bloom filters focused on lookup speed through cache
locality, with a pluggable hash function and an optional keyed (DoS-resistant)
mode.

# Tiers

	New / NewWithEstimates   classic filter: minimum memory, exact target FP
	NewBlocked               cache-local: 1 cache miss per op (~3x faster at
	                         scale), slightly higher FP from uneven block load
	NewBlockedTuned          cache-local with the block count sized to hit the
	                         target FP (costs ~10% more memory)

# Choosing by trust boundary

The right configuration depends on WHO supplies the keys — pick by your trust
boundary, not by guesswork.

Internal / trusted keys — IDs you generate, file paths, cache keys, anything an
attacker cannot choose: optimize for speed. Use the fastest tier that meets your
accuracy budget with the default hash (XXH3) and no seed. There is nothing to
attack, so the unkeyed fast path is the right default:

	f := bloom.NewBlockedTuned(n, fp) // fast: XXH3, unseeded

Public / untrusted keys — anything an external caller can choose: an adversary
who knows your fixed hash can poison the filter (craft inputs that inflate the
false-positive rate until it stops protecting the backend). Key the hash with a
secret seed. The Secured option bundles the conservative choice (a secret seed
plus SipHash, a keyed PRF):

	f := bloom.NewBlockedTuned(n, fp, bloom.Secured(bloom.RandomSeed()))

Rule of thumb: speed is safe for internal APIs — choose the fastest tier at
adequate accuracy; switch to Secured the moment the keys come from a published,
externally reachable surface.

See the README for the full threat model, the format spec, and benchmarks.
*/
package bloom
