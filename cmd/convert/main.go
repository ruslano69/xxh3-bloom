// convert upgrades a serialized blocked filter (v1/v2) to the current v3 format.
//
//	go run ./cmd/convert input.bbf output.bbf
//
// ReadFrom understands every historical version, and WriteTo always emits v3
// (self-describing, endianness-tagged), so conversion is just read-then-write.
package main

import (
	"bufio"
	"fmt"
	"os"

	bloom "github.com/ruslano69/xxh3-bloom"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: convert <input.bbf> <output.bbf>")
		os.Exit(2)
	}
	in, out := os.Args[1], os.Args[2]

	fin, err := os.Open(in)
	must(err)
	defer fin.Close()
	r := bufio.NewReader(fin)

	// Peek the version byte for reporting without consuming the stream.
	head, err := r.Peek(5)
	must(err)
	if string(head[0:4]) != "BBLM" {
		fail("%s is not a blocked filter file (bad magic)", in)
	}
	srcVersion := head[4]

	var f bloom.BlockedFilter
	if _, err := f.ReadFrom(r); err != nil {
		fail("reading %s: %v", in, err)
	}

	if srcVersion == 3 {
		fmt.Printf("%s is already v3 (bits=%d, k=%d, seed=%#x) — rewriting anyway\n",
			in, f.Cap(), f.K(), f.Seed())
	}

	fout, err := os.Create(out)
	must(err)
	w := bufio.NewWriter(fout)
	n, err := f.WriteTo(w)
	must(err)
	must(w.Flush())
	must(fout.Close())

	fmt.Printf("converted %s (v%d) -> %s (v3): bits=%d, k=%d, seed=%#x, %d bytes\n",
		in, srcVersion, out, f.Cap(), f.K(), f.Seed(), n)
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "convert: "+format+"\n", a...)
	os.Exit(1)
}
