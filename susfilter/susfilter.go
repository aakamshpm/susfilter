package susfilter

import (
	"hash/fnv"
	"math"
)

// BloomFilter is a space-efficient probabilistic data structure used to test whether an element might be in a set. It can give false positives .
// (says "maybe present" when it's not), but never false negatives (if it says "definitely not present", it's always right).
type BloomFilter struct {
	bits    []uint64 // packed bit array - each uint64 holds 64 bits, all start at 0
	numHash uint     // number of hash positions per item
	m       uint     // total number of bits in the filter
}

// New creates a BloomFilter sized for the given number of expected items and acceptable false positive rate.
//
// expectedItems: approx number of URLs we plan to store
// falsePositiveRate: what % of wrong answers we are okay with (0.01 = 1%)
func New(expectedItems uint, falsePositiveRate float64) *BloomFilter {
	// calculate how many bits we need (m) using: m = -(n × ln(p)) / (ln2)²
	// core items or stricter rate → more bits needed
	m := optimalNumBits(expectedItems, falsePositiveRate)

	// calculate how many hash positions per item using: k = (m/n) × ln2
	// this is the sweet spot: too few = more false positives, too many = filter fills up fast
	n := optimalNumHash(m, expectedItems)

	return &BloomFilter{
		// (m+63)/64 is ceiling division without floats - tells us how many uint64 boxes we need to hold m bits (each box = 64 bits)
		bits:    make([]uint64, (m+63)/64),
		numHash: n,
		m:       m,
	}
}

// optimalNumBits returns the minimum number of bits (m) needed to store n items
// with false positive rate p. Formula: m = -(n × ln(p)) / (ln2)²
func optimalNumBits(n uint, p float64) uint {
	return uint(math.Ceil(-float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)))
}

// optimalNumHash returns the optimal number of hash positions (k) per item.
// formula: k = (m/n) × ln2
func optimalNumHash(m, n uint) uint {
	return uint(math.Ceil(float64(m) / float64(n) * math.Ln2))
}

// hashers computes two independent hashes for the given item using FNV variants.
// h1 uses FNV-1a (XOR-then-multiply), h2 uses FNV-1 (multiply-then-XOR).
// same input always produces the same two hashes. Different input = different hashes.
func (bf *BloomFilter) hashers(item string) (uint, uint) {
	h1 := fnv.New64a()
	h1.Write([]byte(item))    // feed the URL string as bytes (Write only accepts []byte)
	hash1 := uint(h1.Sum64()) // spit out a deterministic, random-looking number

	h2 := fnv.New64() // different FNV variant → different number for same input
	h2.Write([]byte(item))
	hash2 := uint(h2.Sum64())

	return hash1, hash2
}

// positions generates numHash positions for the item using double hashing.
// Instead of running k different hash functions, we derive all k positions
// from just two hashes: position_i = (h1 + i×h2) % m, where i = 0..k-1
// The % m wraps positions back into the bit array's range (0 to m-1).
func (bf *BloomFilter) positions(item string) []uint {
	h1, h2 := bf.hashers(item)

	positions := make([]uint, bf.numHash) // create a slice with numHash slots (e.g., 7)
	for i := uint(0); i < bf.numHash; i++ {
		positions[i] = (h1 + uint(i)*h2) % bf.m
	}
	return positions
}

// Add marks the item as present in the filter by setting bit positions to 1.
// for each of the k positions: find which box (index) and which bit inside that box (bit), then flip it to 1 using OR.
func (bf *BloomFilter) Add(item string) {
	for _, pos := range bf.positions(item) {
		index := pos / 64          // which uint64 box does this bit live in
		bit := pos % 64            // which bit position inside that box (0-63)
		bf.bits[index] |= 1 << bit // set that bit to 1 - leaves all other bits unchanged
	}
}

// MightContain checks if the item might have been added to the filter.
// for each of the k positions: check if the bit is 1 using AND.
// - If any bit is 0 → the item was definitely never added (no false negatives)
// - If all bits are 1 → the item was probably added (could be a false positive)
func (bf *BloomFilter) MightContain(item string) bool {
	for _, pos := range bf.positions(item) {
		index := pos / 64
		bit := pos % 64

		// AND the box with the mask - if result is 0, this bit was never set to 1
		if bf.bits[index]&(1<<bit) == 0 {
			return false
		}
	}
	return true
}
