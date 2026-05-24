package susfilter

import (
	"math"
	"testing"
)

func TestNew(t *testing.T) {
	t.Run("creates filter with correct bit count", func(t *testing.T) {
		bf := New(10000, 0.01)
		expectedBits := uint(math.Ceil(-10000 * math.Log(0.01) / (math.Ln2 * math.Ln2)))
		if bf.m != expectedBits {
			t.Errorf("m = %d, want %d", bf.m, expectedBits)
		}
		expectedBoxes := uint((expectedBits + 63) / 64)
		if uint(len(bf.bits)) != expectedBoxes {
			t.Errorf("len(bits) = %d, want %d", len(bf.bits), expectedBoxes)
		}
	})
	t.Run("creates filter with correct hash count", func(t *testing.T) {
		bf := New(10000, 0.01)
		expectedHash := uint(math.Ceil(float64(bf.m) / 10000.0 * math.Ln2))
		if bf.numHash != expectedHash {
			t.Errorf("numHash = %d, want %d", bf.numHash, expectedHash)
		}
	})
	t.Run("all bits start at zero", func(t *testing.T) {
		bf := New(10000, 0.01)
		for i, box := range bf.bits {
			if box != 0 {
				t.Errorf("bits[%d] = %d, want 0 — filter should start empty", i, box)
			}
		}
	})
}

func TestAddAndMightContain(t *testing.T) {
	t.Run("item that was added is found", func(t *testing.T) {
		bf := New(10000, 0.01)
		bf.Add("https://malware.com")
		if !bf.MightContain("https://malware.com") {
			t.Error("expected MightContain to return true for added item")
		}
	})
	t.Run("item that was not added returns false most of the time", func(t *testing.T) {
		bf := New(10000, 0.01)
		bf.Add("https://malware.com")
		if bf.MightContain("https://totally-safe.com") {
			t.Log("false positive occurred — this is expected sometimes, but rare")
		}
	})
	t.Run("multiple items that were added are all found", func(t *testing.T) {
		bf := New(10000, 0.01)
		urls := []string{
			"https://malware.com",
			"https://phishing.com",
			"https://trojan.ru",
			"https://ransomware.org",
			"https://spam.net",
		}
		for _, url := range urls {
			bf.Add(url)
		}
		for _, url := range urls {
			if !bf.MightContain(url) {
				t.Errorf("expected MightContain to return true for %q", url)
			}
		}
	})
}
func TestNoFalseNegatives(t *testing.T) {
	t.Run("added items are never reported as absent", func(t *testing.T) {
		bf := New(100000, 0.01)
		for i := 0; i < 10000; i++ {
			bf.Add("url-" + string(rune(i)))
		}
		falseNegatives := 0
		for i := 0; i < 10000; i++ {
			if !bf.MightContain("url-" + string(rune(i))) {
				falseNegatives++
			}
		}
		if falseNegatives > 0 {
			t.Errorf("got %d false negatives — Bloom filters should never have false negatives", falseNegatives)
		}
	})
}

func TestFalsePositiveRate(t *testing.T) {
	t.Run("false positive rate is around the expected rate", func(t *testing.T) {
		n := uint(100000)
		p := 0.01
		bf := New(n, p)
		for i := 0; i < int(n); i++ {
			bf.Add("stored-url-" + string(rune(i)))
		}
		falsePositives := 0
		testCount := 10000
		for i := 0; i < testCount; i++ {
			if bf.MightContain("not-stored-url-" + string(rune(i))) {
				falsePositives++
			}
		}
		actualRate := float64(falsePositives) / float64(testCount)
		if actualRate > 0.05 {
			t.Errorf("false positive rate = %.4f, want around %.4f — should not exceed 5%%", actualRate, p)
		}
	})
}
