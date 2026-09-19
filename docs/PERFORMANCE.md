# Performance notes

Background for the caching and header-hiding settings documented in the [README](../README.md#configuration). Nothing here is needed to use the filter.

**Short version:** the certificate cache is on by default and keyed by the header value itself. Measured against no cache, on hardware without SHA-256 acceleration and with the working set inside the cache, it is 26x faster for an Envoy `Cert=` header, 2.3x for a Gorouter raw base64 certificate and 4.5x for a CF app-identity header, and allocates less in every case. Turn it off when more distinct certificates are in rotation than the cache holds.

CPU profiling on CF test systems showed hotspots in both `X509Certificate` construction and XFCC header processing. A cache hit removes both, which is why the parsed bundle is cached rather than just the certificate.

An earlier revision keyed the cache on a SHA-256 digest of the header. That cost more than it saved -- digesting 1.4-1.8 KB is slower than parsing the certificate on hardware without SHA extensions -- and the numbers below are the reason the key changed. The digest variant is still in the benchmark for comparison.

## How the cache works

When enabled, parsed results are cached and reused across requests for the same header entry. The key is the header entry exactly as received -- not the router-supplied `Hash=` field, which external clients could inject when header stripping is disabled, and not a digest. Only a request carrying the byte-for-byte same header value can hit, and `String.equals()` confirms it.

**Every entry is cached, including identity-only ones.** The digest is computed and checked before it is known whether the entry carries a certificate, so the parsed result is stored on a miss regardless -- including CF app-identity headers that carry only `Hash=`/`Subject=`, and `Chain=`-only entries that map no certificate. Entries whose parse fails are not cached: the exception propagates out of `getOrCompute` and nothing is stored.

**Multiple headers vs. a certificate chain.** A request can carry multiple `X-Forwarded-Client-Cert` entries -- as separate header lines or comma-joined in one line -- typically from multiple hops each terminating their own mTLS connection and appending their own entry. Each entry is a **separate leaf certificate**, cached **independently** under its own key; a hit or miss on one entry never affects another, and the mapped `X509Certificate[]` attribute preserves header order regardless of cache state. This is unrelated to a single certificate's **trust chain** (the XFCC `Chain=` field) -- that field is not supported for certificate mapping.

## Benchmark method

`java-buildpack-client-certificate-mapper-benchmark` is a JMH module, excluded from the default build:

```shell
$ ./mvnw -Pbenchmarks -DskipTests package
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 1
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 4
```

`XfccResolverBenchmark` calls `XfccResolver.resolve()` once per operation, with the cache enabled (size 128, so ~256 entries across both generations) and disabled, which is the default, over three header forms and three working-set sizes. `cacheEnabled` is the production path, which keys on the header value. A third variant, `cacheEnabledDigestKey`, uses the same cache and the same parse path but keys on a SHA-256 digest of the header -- the superseded design, kept so the decision can be re-measured on other hardware, particularly CPUs with SHA extensions.

**Every variant builds a fresh `String` per operation**, because that is what a request produces: the header value is substring-parsed per request, so its `hashCode` has never been computed and it is never the same object the cache stored. Reusing one instance across iterations lets `hashCode` be cached and `equals()` short-circuit on reference identity, which reports the raw-key design at ~14 ns/op -- roughly two orders of magnitude too fast. Any benchmark of a keying strategy that does not build a fresh key per operation is measuring nothing useful. `-prof gc` reports `gc.alloc.rate.norm`, the bytes allocated per operation. Certificates are RSA 2048 leaves with a CF-style Subject DN, generated at setup from a fixed seed.

The three forms map to real deployments:

| Form | Where it comes from | What a cache hit skips |
| --- | --- | --- |
| `CERT_FIELD` | Envoy `Cert=`, URL-encoded PEM | URL-decode, PEM decode, ASN.1 parse |
| `RAW_BASE64` | CF Gorouter `xfcc_format: raw`, i.e. client certificates arriving from outside the platform | base64 decode, ASN.1 parse |
| `IDENTITY_ONLY` | CF app-identity on an mTLS domain (`Hash=` + `Subject=`) | field scan and Subject DN parse; there is no certificate |

**Results below were measured on a machine with no SHA-256 hardware acceleration** (Intel i7-3615QM, 4 cores / 8 threads, OpenJDK 25.0.2, Linux; `openssl speed sha256` reports ~282 MB/s at 1 KB blocks). This matters more than anything else in this document: the cached path must digest the whole header on every request, which costs ~6 us for a 1.7 KB header here. A CPU with the SHA extensions (any recent x86-64 or ARM server part) digests the same header in roughly 1 us, which shifts every "cache enabled" number below by about 5 us in the cache's favour. Re-run the benchmark on your own hardware before drawing conclusions.

## Results

Average time per `resolve()` call and bytes allocated per call, for three designs: no cache, the
current cache keyed by a SHA-256 digest of the header, and the same cache keyed by the header value
itself. `workingSet` is the number of distinct certificates in rotation; the cache holds ~256, so
512 is the thrash case.

**One thread, working set 16 (everything hits):** value-key figures re-verified against the shipped implementation (2.1 / 1.6 / 0.33 us), matching the standalone variant they were measured with.

| Form | No cache | Digest key | Raw-value key |
| --- | --- | --- | --- |
| Envoy `Cert=` PEM | 54.0 us / 24441 B | 12.9 us / 4601 B | **2.1 us / 1895 B** |
| Gorouter raw base64 | 3.6 us / 9304 B | 9.9 us / 3680 B | **1.6 us / 1456 B** |
| CF app-identity | 1.5 us / 1680 B | 2.4 us / 1400 B | **0.3 us / 304 B** |

**Four threads, working set 16:**

| Form | No cache | Digest key | Raw-value key |
| --- | --- | --- | --- |
| Envoy `Cert=` PEM | 57.6 us | 23.4 us | **3.6 us** |
| Gorouter raw base64 | 7.2 us | 20.0 us | **2.8 us** |
| CF app-identity | 2.6 us | 4.9 us | **0.5 us** |

**One thread, working set 512 (mostly misses):**

| Form | No cache | Digest key | Raw-value key |
| --- | --- | --- | --- |
| Envoy `Cert=` PEM | **55.0 us** | 70.0 us | 57.9 us |
| Gorouter raw base64 | **4.0 us** | 14.2 us | 5.6 us |
| CF app-identity | **1.8 us** | 4.6 us | 2.3 us |

## What the numbers support

- **The cache idea is sound; the key derivation is what costs.** Keyed by the header value, every
  form gets faster and allocates less: 26x for Envoy `Cert=`, 2.3x for raw base64, 4.5x for
  identity-only. Keyed by a SHA-256 digest, only `Cert=` comes out ahead, because the digest of a
  1.4-1.8 KB header costs more here than the parse it avoids.
- **`String.hashCode()` is the cheap hash.** About one cycle per byte, against roughly ten for
  SHA-256 without hardware acceleration, and it is computed once per request either way -- the
  digest is pure addition on top.
- **Missing is cheap with a raw key, expensive with a digest.** At 512 distinct certificates
  against ~256 slots, the digest key costs 27% (Envoy) to 3.5x (raw base64) over no cache; the
  raw-value key costs 5% to 37%. A cache that mostly misses stops being a catastrophe.
- **Identity-only headers only make sense to cache with a cheap key.** 1.5 us to 0.3 us with a raw
  key; 1.5 us to 2.4 us with a digest.
- **Contention does not change the ranking.** At four threads every design slows down, and the
  ordering is unchanged.

## Cache key: digest vs. raw value

`CacheKeyBenchmark` isolates the key strategy, looking up a pre-populated map from a freshly built `String` -- which is what a request produces, since the header value is substring-parsed per request and its `hashCode` has never been computed.

| Key strategy | 1.3 KB header (us) | 2.4 KB header (us) | B/op at 1.3 KB |
| --- | --- | --- | --- |
| SHA-256 hex digest | 9.4 | 16.4 | 3368 |
| Raw header value | **1.4** | **2.6** | **1344** |

On this hardware the raw value is the faster key by ~6.6x, because `String.hashCode()` costs about one cycle per byte where SHA-256 costs about ten. With SHA extensions the two come out close to even. **An earlier version of this document claimed the digest key was ~14.6x faster than a raw-value key; that claim does not reproduce and has been removed.** The likely explanation is that the earlier measurement computed the digest outside the timed region, charging the digest strategy nothing for work the request path performs on every call.

The digest key's one remaining advantage is memory: a 64-character key, against a value key that retains the whole header string -- roughly 1.4-1.8 KB per entry for CF-shaped headers, proportionally more where `maxHttpHeaderSize` has been raised. The filter now pays that memory for the speed, and sizing is controlled with `cache.size`. A value key also removes the collision question entirely -- `equals()` confirms every hit -- at the cost of being the caller-supplied string itself, which `ConcurrentHashMap` handles by treeifying degenerate buckets.

## Memory

Two generations of up to `cache.size` entries each (128 by default). A key is the header string itself, 1.4-1.8 KB for CF-shaped headers. Each value is a `ParsedXfcc` holding the parsed `X509Certificate` plus the `XfccEntry` it came from, which retains the *recognised field values* -- `Cert=`, `Subject=` and `Chain=` substrings. Unknown fields are skipped and not retained.

For CF-shaped headers (1-2 KB) a full cache is roughly **1 MB** of values plus a comparable amount of keys. The true bound is `2 x cache.size` multiplied by the largest header the container accepts: at Tomcat's default 8 KB `maxHttpHeaderSize` that is ~2 MB, and a deployment that raises the limit to 48 KB to accommodate large chains bounds it at ~12 MB. Where the fronting proxy does not sanitize the header, the distinctness of those entries is caller-controlled, so the upper bound rather than the typical figure is the one to plan for.

## Header hiding

Hiding the header (`org.cloudfoundry.router.certificate.header.hide`) keeps large base64 certificate values out of downstream filters that iterate or log all headers. Measured separately from the JMH runs above, with a Spring Boot app behind `CommonsRequestLoggingFilter` (which reads and logs all request headers on every request) and the raw XFCC header as forwarded by CF Gorouter. `byte[]` allocation captured via Java Flight Recorder over a 40-second run at 500 requests/second:

| `header.hide` | `cache.enabled` | Request logging filter | `byte[]` allocation |
|---|---|---|---|
| `false` | `false` | enabled | 1.47 GiB |
| `true` | `false` | enabled | 791 MB |
| `true` | `true` | enabled | 547 MB |
| `true` | `true` | disabled | 60.5 MB |

The largest impact by far is the `byte[]` allocations inside the logging filter itself -- hiding the header is what removes most of them; caching removes the remaining repeated certificate parsing on top of that. This run predates the JMH module and its environment is not recorded beyond the settings above.

Hiding the header does not free the underlying string memory during the request -- it prevents downstream code from reading it. Memory is reclaimed when the request completes and the original request object is GC'd. The wrapper is only created when the header is actually present, so there is no overhead for requests without a client certificate.
