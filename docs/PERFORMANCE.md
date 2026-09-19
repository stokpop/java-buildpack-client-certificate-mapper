# Performance notes

Background for the caching and header-hiding settings documented in the [README](../README.md#configuration). Nothing here is needed to use the filter.

**Short version:** the certificate cache is a clear win for headers that carry a full certificate as URL-encoded PEM, a wash or a loss for bare base64 DER and for identity-only headers, and a loss for every form once the number of distinct certificates in rotation exceeds `2 x cache.size`. Whether it wins on CPU time at all depends on whether the machine has SHA-256 hardware acceleration. It reduces allocation in every case where it hits.

## How the cache works

Parsed results are cached and reused across requests for the same header entry. The key is a 64-character SHA-256 hex digest of the header entry exactly as received -- not the raw string, and not the router-supplied `Hash=` field, which external clients could inject when header stripping is disabled. Only a request carrying the byte-for-byte same header value can hit. The digest is taken over the header string as received (URL-encoded PEM or base64 DER), not over the decoded DER bytes, so it intentionally differs from the Envoy XFCC `Hash=` field and the two are not cross-comparable.

**Every entry is cached, including identity-only ones.** The digest is computed and checked before it is known whether the entry carries a certificate, so the parsed result is stored on a miss regardless -- including CF app-identity headers that carry only `Hash=`/`Subject=`, and `Chain=`-only entries that map no certificate. Entries whose parse fails are not cached: the exception propagates out of `getOrCompute` and nothing is stored.

**Multiple headers vs. a certificate chain.** A request can carry multiple `X-Forwarded-Client-Cert` entries -- as separate header lines or comma-joined in one line -- typically from multiple hops each terminating their own mTLS connection and appending their own entry. Each entry is a **separate leaf certificate**, cached **independently** under its own key; a hit or miss on one entry never affects another, and the mapped `X509Certificate[]` attribute preserves header order regardless of cache state. This is unrelated to a single certificate's **trust chain** (the XFCC `Chain=` field) -- that field is not supported for certificate mapping.

## Benchmark method

`java-buildpack-client-certificate-mapper-benchmark` is a JMH module, excluded from the default build:

```shell
$ ./mvnw -Pbenchmarks -DskipTests package
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 1
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 4
```

`XfccResolverBenchmark` calls `XfccResolver.resolve()` once per operation, with the cache enabled (size 128, so ~256 entries across both generations) and disabled, over three header forms and three working-set sizes. `-prof gc` reports `gc.alloc.rate.norm`, the bytes allocated per operation. Certificates are RSA 2048 leaves with a CF-style Subject DN, generated at setup from a fixed seed.

The three forms map to real deployments:

| Form | Where it comes from | What a cache hit skips |
| --- | --- | --- |
| `CERT_FIELD` | Envoy `Cert=`, URL-encoded PEM | URL-decode, PEM decode, ASN.1 parse |
| `RAW_BASE64` | CF Gorouter `xfcc_format: raw`, i.e. client certificates arriving from outside the platform | base64 decode, ASN.1 parse |
| `IDENTITY_ONLY` | CF app-identity on an mTLS domain (`Hash=` + `Subject=`) | field scan and Subject DN parse; there is no certificate |

**Results below were measured on a machine with no SHA-256 hardware acceleration** (Intel i7-3615QM, 4 cores / 8 threads, OpenJDK 25.0.2, Linux; `openssl speed sha256` reports ~282 MB/s at 1 KB blocks). This matters more than anything else in this document: the cached path must digest the whole header on every request, which costs ~6 us for a 1.7 KB header here. A CPU with the SHA extensions (any recent x86-64 or ARM server part) digests the same header in roughly 1 us, which shifts every "cache enabled" number below by about 5 us in the cache's favour. Re-run the benchmark on your own hardware before drawing conclusions.

## Results: one thread

Average time per `resolve()` call and bytes allocated per call. `workingSet` is the number of distinct certificates in rotation; 512 exceeds the ~256 the cache holds.

| Form | Working set | No cache (us) | Cache (us) | No cache (B/op) | Cache (B/op) |
| --- | --- | --- | --- | --- | --- |
| `CERT_FIELD` | 1 | 53.1 | **12.8** | 22128 | **2664** |
| `CERT_FIELD` | 16 | 53.1 | **12.5** | 22270 | **2658** |
| `CERT_FIELD` | 512 | **54.6** | 69.8 | **22536** | 25067 |
| `RAW_BASE64` | 1 | **3.4** | 9.7 | 7848 | **2224** |
| `RAW_BASE64` | 16 | **3.4** | 9.9 | 7848 | **2224** |
| `RAW_BASE64` | 512 | **3.7** | 13.9 | **7848** | 10245 |
| `IDENTITY_ONLY` | 1 | **1.5** | 2.4 | 1376 | **1096** |
| `IDENTITY_ONLY` | 16 | **1.4** | 2.4 | 1376 | **1072** |
| `IDENTITY_ONLY` | 512 | **1.7** | 4.6 | **1376** | 2567 |

## Results: four threads

Same benchmark at `-t 4` on four physical cores. Per-operation averages rise for both variants under contention; the relative picture is unchanged.

| Form | Working set | No cache (us) | Cache (us) |
| --- | --- | --- | --- |
| `CERT_FIELD` | 16 | 103.9 | **29.5** |
| `CERT_FIELD` | 512 | **111.3** | 127.6 |
| `RAW_BASE64` | 16 | **9.4** | 22.6 |
| `RAW_BASE64` | 512 | **9.2** | 29.4 |
| `IDENTITY_ONLY` | 16 | **3.4** | 5.5 |
| `IDENTITY_ONLY` | 512 | **4.0** | 9.4 |

## What the numbers support

- **URL-encoded PEM (`Cert=`) is where the cache pays.** 53 us to 12.5 us, and 22 KB to 2.7 KB per call: the URL-decode plus PEM plus ASN.1 path is expensive enough to dwarf the digest even on hardware this slow at SHA-256.
- **Bare base64 DER costs more time with the cache than without, on this hardware.** Decoding and parsing the certificate takes ~3.4 us; digesting the header to look it up takes ~6 us. The cache still cuts allocation by 3.5x (7.8 KB to 2.2 KB). On a CPU with SHA extensions the digest drops to roughly 1 us and this form becomes a modest time win too -- but that is an extrapolation, not a measurement.
- **Identity-only headers do not justify caching on time.** There is no certificate to parse, so the cache trades a ~1.4 us field scan for a ~2.4 us digest-and-lookup. The allocation saving is ~300 B per call. This is the weakest case for the current default.
- **Exceeding the cache costs everyone.** At 512 distinct certificates against ~256 slots, every form is slower with the cache on, by 28% (`CERT_FIELD`) to 3.8x (`RAW_BASE64`), and allocates more. Deployments fronting more concurrent client certificates than `2 x cache.size` should raise `cache.size` or disable the cache.
- **The cache never makes allocation worse while it hits**, and hitting is the common case in CF, where a small number of calling app instances repeat constantly.

## Cache key: digest vs. raw value

`CacheKeyBenchmark` isolates the key strategy, looking up a pre-populated map from a freshly built `String` -- which is what a request produces, since the header value is substring-parsed per request and its `hashCode` has never been computed.

| Key strategy | 1.3 KB header (us) | 2.4 KB header (us) | B/op at 1.3 KB |
| --- | --- | --- | --- |
| SHA-256 hex digest | 9.4 | 16.4 | 3368 |
| Raw header value | **1.4** | **2.6** | **1344** |

On this hardware the raw value is the faster key by ~6.6x, because `String.hashCode()` costs about one cycle per byte where SHA-256 costs about ten. With SHA extensions the two come out close to even. **An earlier version of this document claimed the digest key was ~14.6x faster than a raw-value key; that claim does not reproduce and has been removed.** The likely explanation is that the earlier measurement computed the digest outside the timed region, charging the digest strategy nothing for work the request path performs on every call.

The digest key remains defensible on memory grounds -- a 64-character key instead of retaining a second reference to a 1-2 KB header string -- and on not keying on attacker-supplied content length. It is not defensible as a speed optimisation.

## Memory

Two generations of up to `cache.size` entries each (128 by default). Keys are 64-character digests, negligible next to the values. Each value is a `ParsedXfcc` holding the parsed `X509Certificate` plus the `XfccEntry` it came from, which retains the *recognised field values* -- `Cert=`, `Subject=` and `Chain=` substrings. Unknown fields are skipped and not retained.

For CF-shaped headers (1-2 KB) a full cache is roughly **1.5 MB**. The true bound is `2 x cache.size` multiplied by the largest header the container accepts: at Tomcat's default 8 KB `maxHttpHeaderSize` that is ~2 MB, and a deployment that raises the limit to 48 KB to accommodate large chains bounds it at ~12 MB. Where the fronting proxy does not sanitize the header, the distinctness of those entries is caller-controlled, so the upper bound rather than the typical figure is the one to plan for.

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
