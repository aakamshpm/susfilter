package susfilter

import (
	"hash/fnv"
	"math"
)

type BloomFilter struct {
	bits    []uint64
	numHash uint
	m       uint
}

func New(expectedItems uint, falsePositiveRate float64) *BloomFilter {
	m := optimalNumBits(expectedItems, falsePositiveRate)
	n := optimalNumHash(m, expectedItems)

	return &BloomFilter{
		bits:    make([]uint64, (m+63)/64),
		numHash: n,
		m:       m,
	}
}

func optimalNumBits(n uint, p float64) uint {
	return uint(math.Ceil(-float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)))
}

func optimalNumHash(m, n uint) uint {
	return uint(math.Ceil(float64(m) / float64(n) * math.Ln2))
}

func (bf *BloomFilter) hashers(item string) (uint, uint) {
	h1 := fnv.New64a()
	h1.Write([]byte(item))
	hash1 := uint(h1.Sum64())

	h2 := fnv.New64()
	h2.Write([]byte(item))
	hash2 := uint(h2.Sum64())

	return hash1, hash2
}
