# susfilter

a bloom filter implementation in go that detects malicious urls. but honestly, it can be used to check if _anything_ is in a set - urls, usernames, whatever. malicious urls is just the use case i went with.

## why this project

i was learning about bloom filters and go at the same time. instead of just reading theory and forgetting it, i wanted to build something real. so here it is - a probabilistic data structure that tells you if something is **probably in a set** or **definitely not in a set**. no in-between.

## how bloom filters work (the short version)

imagine a row of switches, all starting OFF (0). when you want to remember a url, you hash it to get a few positions, and flip those switches ON (1). later, to check if a url was ever added, you hash it again, go to those same positions, and see if the switches are ON.

- if any switch is OFF → **definitely never added** (no false negatives, ever)
- if all switches are ON → **probably was added** (could be a false positive, other urls might have flipped those switches too)

that's it. that's the whole concept.

### the math behind sizing

you tell the filter two things: how many items you expect to store (`n`), and what false positive rate you're okay with (`p`). it then calculates:

- **how many bits you need** (`m`): `m = -(n × ln(p)) / (ln2)²` - more items or stricter rate → more bits
- **how many hash positions per item** (`k`): `k = (m/n) × ln2` - the sweet spot between too few (more false positives) and too many (filter fills up faster)

### how hashing works (double hashing)

instead of running 7 different hash algorithms (which is slow), we run just 2 and derive the rest with simple math:

```
position_i = (h1 + i × h2) % m     where i = 0, 1, 2, ..., k-1
```

same url → same h1 and h2 → same positions. different url → different everything. cheap and effective.

## how the code is structured

```
susfilter/
├── susfilter.go          # the bloom filter implementation
├── susfilter_test.go     # tests
cmd/
└── urlchecker/
    └── main.go           # cli app that uses the filter to check urls
```

### the core api

```go
bf := susfilter.New(10000, 0.01)   // expect 10k items, 1% false positive rate

bf.Add("https://malware-site.com")  // add a url to the filter

bf.MightContain("https://malware-site.com")  // true  - probably was added
bf.MightContain("https://google.com")         // false - definitely was never added
```

that's it. three methods. `New`, `Add`, `MightContain`. no pretending it's more complex than it is - the method is literally called `MightContain` because it _might_ contain the item, it doesn't guarantee it. (that's why it's called a probabilistic data structure)

### how the url checker works

the cli app (`cmd/urlchecker/main.go`) is the practical use case:

1. preload the bloom filter with known malicious urls
2. take a url from command line
3. check the bloom filter first
4. if `MightContain` returns `false` → definitely safe, no database call needed
5. if `MightContain` returns `true` → check the actual malicious url list to confirm (this simulates the database lookup)

this is exactly how browsers and security tools use bloom filters in production - as a fast first filter before hitting the actual database.

## how to run it

### prerequisites

- go 1.21 or later

### clone and run the cli

```bash
git clone https://github.com/aakmshpm/susfilter.git
cd susfilter
go run cmd/urlchecker/main.go https://malware-site.com
```

output:

```
CONFIRMED: https://malware-site.com is in the malicious URL database
```

```bash
go run cmd/urlchecker/main.go https://google.com
```

output:

```
SAFE: https://google.com is definitely NOT in the malicious URL database
```

### run the tests

```bash
go test ./susfilter/ -v
```

## how efficient is this

here's the whole point - why bloom filters exist:

| approach | memory for 10k urls | lookup time | false negatives |
|---|---|---|---|
| storing full urls in a set | ~600 KB | O(n) or O(log n) depending on structure | none, but slow and heavy |
| redis cache | ~600 KB + network overhead | ~1-5 ms per lookup (network round trip) | none, but expensive |
| bloom filter | ~12 KB at 1% fp rate | nanoseconds (in-memory bitwise ops) | none. zero. ever. |

the tradeoff: you accept ~1% false positives (unnecessary database lookups) to eliminate 99% of database queries entirely. in a system processing millions of url checks, that's a massive win.

### benchmark

run it yourself:

```bash
go test ./susfilter/ -bench=. -benchmem
```

## limitations

- **false positives** - the filter can say an item is present when it's not (~1% of the time at p=0.01)
- **no deletion** - you can add items but you can't remove them (removing a bit could break other items). if you need deletion, look into counting bloom filters
- **fixed capacity** - sized at creation time. if you add way more items than expected, the false positive rate goes up

## what i learned

- how bloom filters work under the hood - the math, the bit manipulation, the hashing strategy
- bitwise operators for real - OR to set bits, AND to check bits, left shift to create masks
