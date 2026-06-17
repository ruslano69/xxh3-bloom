package main

import (
	"fmt"

	xxhbloom "github.com/ruslano69/xxh3-bloom"
)

func main() {
	f := xxhbloom.NewWithEstimates(1_000_000, 0.01)
	fmt.Printf("Filter: m=%d bits (%.1f KB), k=%d hash functions\n\n",
		f.Cap(), float64(f.Cap())/8/1024, f.K())

	s3Keys := []string{
		"prod-bucket/users/42/avatar.jpg",
		"prod-bucket/users/42/cover.png",
		"prod-bucket/logs/2026-06-17/app.log",
		"prod-bucket/configs/service.yaml",
	}
	for _, k := range s3Keys {
		f.Add([]byte(k))
	}

	candidates := append(s3Keys,
		"prod-bucket/users/42/nonexistent.gif",
		"prod-bucket/hacker_exploit.exe",
		"totally-random-key-xyzzy",
	)
	fmt.Println("Membership checks:")
	for _, k := range candidates {
		if f.Test([]byte(k)) {
			fmt.Printf("  MAYBE EXISTS  %s\n", k)
		} else {
			fmt.Printf("  ABSENT        %s\n", k)
		}
	}
}
