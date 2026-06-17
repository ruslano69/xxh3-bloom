package bloom

// Option configures a filter at construction. Pass any number of options to the
// constructors; unset options keep their defaults (seed 0, hash XXH3).
type Option func(*config)

type config struct {
	seed uint64
	hash HashKind
}

func defaultConfig() config {
	return config{seed: 0, hash: XXH3}
}

func buildConfig(opts []Option) config {
	c := defaultConfig()
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithSeed keys the filter's hash with seed, turning the hash into a keyed
// function. A secret per-process seed (see RandomSeed) defeats offline
// filter-poisoning. seed 0 (the default) is the unseeded scheme.
func WithSeed(seed uint64) Option {
	return func(c *config) { c.seed = seed }
}

// WithHash selects the hash function (default XXH3). See HashKind.
func WithHash(kind HashKind) Option {
	return func(c *config) { c.hash = kind }
}
