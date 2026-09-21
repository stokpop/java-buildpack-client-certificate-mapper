# Performance notes

Background for the caching and header-hiding settings documented in the [README](../README.md#configuration). Nothing here is needed to use the filter.

**The thing worth knowing first:** the JVM already caches parsed certificates. `CertificateFactory.generateCertificate()` consults `sun.security.provider.X509Factory.certCache` -- 750 entries, soft references, keyed by the decoded DER -- before it parses anything. Any measurement of a certificate cache that stays under 750 distinct certificates is therefore measuring against a baseline that is already cached, and understates what a parse costs: a cold parse costs 16.1 us and ~28 KB allocated per call against the 5.2 us and ~9 KB a warm JDK cache suggests. That cache is also JVM-wide, soft-referenced, reached under a lock taken on every lookup, and does nothing for XFCC field scanning or Subject DN parsing -- which is what this filter's cache adds, and why it is worth most exactly where the JDK's stops helping. Details in [The JDK already caches parsed certificates](#the-jdk-already-caches-parsed-certificates).

**Short version:** the certificate cache is off by default -- opt in with `org.cloudfoundry.router.certificate.cache.enabled=true` -- and is keyed by the header value itself. Against no cache, on hardware without SHA-256 acceleration and with the working set inside the cache, it is 8.2x faster for an Envoy `Cert=` header, 2.3x for a Gorouter raw base64 certificate and 4.6x for a CF app-identity header, and allocates less in every case. Against a working set large enough to defeat the JDK's own certificate cache, the raw base64 figure grows to 6.0x. Size `cache.size` to the number of distinct client certificates you serve; a cache that mostly misses is overhead.

It stays opt-in until there is field data: everything here is one machine against synthetic certificates, and the open questions -- a sensible default size, what chain-bearing headers cost, whether a byte-based bound beats an entry count -- want production traffic.

CPU profiling on CF test systems showed hotspots in both `X509Certificate` construction and XFCC header processing, which is why the parsed bundle is cached rather than just the certificate.

## Armored PEM costs more than the certificate it carries

An Envoy `Cert=` header is URL-encoded PEM: the certificate's DER bytes base64-encoded, wrapped in `-----BEGIN/END CERTIFICATE-----` lines -- the *armor* -- and then percent-encoded. Handing that armored text to `CertificateFactory`, as this filter did until the `Cert=` path was changed, costs far more than parsing the same certificate from DER -- and the cost is the armor reader, not the ASN.1 parse: both forms are served by the JDK's certificate cache, and repeat parses return the identical instance either way. Per parse, standalone probe (not JMH), one thread:

| Provider | Working set | PEM in | DER in |
| --- | --- | --- | --- |
| `SUN` | 16 (JDK cache hits) | 51.9 us | **2.8 us** |
| `SUN` | 2000 (JDK cache misses) | 63.8 us | **15.2 us** |
| BouncyCastle | 16 | 72.4 us | **11.3 us** |
| BouncyCastle | 2000 | 72.5 us | **10.5 us** |

The armored path has form here: [JDK-8179389][jdk-8179389] found `X509Factory` reading PEM through a 2 KB buffer that grew 1 KB at a time -- about 10,000 array copies for a 10 MB file, and a 33 MB CRL taking six minutes. It was fixed in JDK 10 by decoding the stream with `Base64.getMimeDecoder()`. That fix targeted CRL-sized input; a 1.5 KB certificate still measures as above on JDK 25, so what remains is the armor scanning in `readOneBlock`, not buffer copying.

So the filter decodes PEM to DER itself before calling the factory. That, plus dropping a failed base64 decode that threw on every `Cert=` header, is worth **3.0x on the uncached Envoy path: 75.1 us before, 24.9 us after**, both measured in one JVM over the same corpus. **The Envoy speedup attributed to the cache in an earlier revision -- 26x -- was mostly this, not the cache.** Against the corrected baseline the cache is worth 8.2x. The other forms never carried armor and are unchanged.

An earlier revision also keyed the cache on a SHA-256 digest of the header: digesting 1.4-1.8 KB is slower than parsing the certificate without SHA extensions, which is why the key changed. The digest columns below record that comparison; the variant itself is no longer in the benchmark.

## How the cache works

Parsed results are reused across requests for the same header entry. The key is the entry exactly as received -- not the router-supplied `Hash=` field, which external clients could inject when header stripping is disabled, and not a digest. Only a byte-for-byte identical header value can hit, and `String.equals()` confirms it.

**Every entry is cached, including identity-only ones**: CF app-identity headers carrying only `Hash=`/`Subject=`, and `Chain=`-only entries that map no certificate. Entries whose parse fails are not cached -- the exception propagates out of `getOrCompute` and nothing is stored.

**Multiple headers vs. a certificate chain.** A request can carry multiple XFCC entries -- separate header lines or comma-joined -- typically from hops that each terminated their own mTLS connection. Each entry is a **separate leaf certificate**, cached **independently** under its own key; a hit or miss on one never affects another, and the mapped `X509Certificate[]` preserves header order regardless of cache state. This is unrelated to a single certificate's **trust chain** (the XFCC `Chain=` field), which is not supported for certificate mapping.

## Benchmark method

`java-buildpack-client-certificate-mapper-benchmark` is a JMH module, excluded from the default build:

```shell
$ ./mvnw -Pbenchmarks -DskipTests package
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 1
$ java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 4
```

`XfccResolverBenchmark` calls `XfccResolver.resolve()` once per operation, cache enabled (size 128, so ~256 entries across both generations) and disabled, over three header forms and three working-set sizes. `cacheEnabled` is the production path, keyed on the header value. The digest-keyed variant it replaced was measured the same way and then removed; `CacheKeyBenchmark` still isolates the two key strategies, which is the comparison worth re-running on a CPU with SHA extensions.

**Every variant builds a fresh `String` per operation**, as a request does: the header value is substring-parsed per request, so its `hashCode` has never been computed and it is never the object the cache stored. Reusing one instance lets `hashCode` be cached and `equals()` short-circuit on identity, reporting the raw-key design at ~14 ns/op -- two orders of magnitude too fast. A keying benchmark without a fresh key per operation measures nothing. `-prof gc` reports `gc.alloc.rate.norm`, bytes per operation. Certificates are RSA 2048 leaves with a CF-style Subject DN from a fixed seed.

| Form | Where it comes from | What a cache hit skips |
| --- | --- | --- |
| `CERT_FIELD` | Envoy `Cert=`, URL-encoded PEM | URL-decode, PEM-to-DER decode, ASN.1 parse |
| `RAW_BASE64` | CF Gorouter `xfcc_format: raw`, i.e. certificates arriving from outside the platform | base64 decode, ASN.1 parse |
| `IDENTITY_ONLY` | CF app-identity on an mTLS domain (`Hash=` + `Subject=`) | field scan and Subject DN parse; there is no certificate |

**The measurement setup**, which matters more than any single number here: a 2012 Mac mini running Linux -- bare metal, so no hypervisor steal time or noisy neighbours -- with an Intel i7-3615QM, 4 physical cores / 8 threads, and Liberica OpenJDK 25.0.2 unless a row says 27, which is Liberica OpenJDK 27+36 (GA, 2026-09-15). It has **no SHA-256 hardware acceleration** -- `sha_ni` is absent from `/proc/cpuinfo`, as it is on every pre-2016 Intel part -- which is why a digest cache key measured so badly here: `CacheKeyBenchmark` below puts it at 13.1 us against 2.0 us for the raw value. On a CPU with the SHA extensions the digest is far cheaper and that gap narrows; how far is not measured here, so treat the key choice as re-checkable rather than settled if your hardware has them.

Turbo is **disabled** (`intel_pstate/no_turbo=1`) and the governor set to `performance`, so every core runs at the 2.3 GHz base clock, and each benchmark JVM is pinned with `taskset -c 0-3` to the four physical cores, one thread per core rather than two sharing an SMT pair. Package temperature settles at ~76 C, so nothing throttles. This is not fussiness: with turbo enabled, a single-threaded run clocks up to 3.3 GHz while a four-thread run throttles below base, which inflates single-thread results and deflates multi-thread ones -- enough on its own to make a scaling ratio look like 1.0x when it is 1.4x. Absolute numbers here are therefore ~40% slower than a turbo-enabled run would report, and the ratios are the part worth reading.

## Results

Time per `resolve()` call and bytes allocated per call, for three designs: no cache, cache keyed by a SHA-256 digest of the header, cache keyed by the header value. `workingSet` is the number of distinct certificates in rotation; the cache holds ~256, so 512 is the thrash case.

**One thread, working set 16 (everything hits):**

| Form | Provider | No cache | Cached | Gain |
| --- | --- | --- | --- | --- |
| Envoy `Cert=` PEM | `SUN` | 24.3 us / 20814 B | **3.0 us / 1899 B** | 8.2x |
| Envoy `Cert=` PEM | `BC` | 34.8 us / 24891 B | **3.0 us / 1903 B** | 11.7x |
| Gorouter raw base64 | `SUN` | 5.2 us / 9304 B | **2.3 us / 1456 B** | 2.3x |
| Gorouter raw base64 | `BC` | 14.1 us / 13112 B | **2.3 us / 1456 B** | 6.2x |
| CF app-identity | `SUN` | 2.1 us / 1680 B | **0.5 us / 304 B** | 4.6x |
| CF app-identity | `BC` | 2.1 us / 1680 B | **0.5 us / 304 B** | 4.6x |

**Four threads, working set 16:**

| Form | Provider | No cache | Cached | Gain |
| --- | --- | --- | --- | --- |
| Envoy `Cert=` PEM | `SUN` | 25.2 us | **3.0 us** | 8.4x |
| Envoy `Cert=` PEM | `BC` | 36.4 us | **3.0 us** | 12.1x |
| Gorouter raw base64 | `SUN` | 8.2 us | **2.3 us** | 3.5x |
| Gorouter raw base64 | `BC` | 14.9 us | **2.3 us** | 6.4x |
| CF app-identity | `SUN` | 2.2 us | **0.5 us** | 4.5x |
| CF app-identity | `BC` | 2.5 us | **0.5 us** | 5.4x |

The cached column barely moves across providers or thread counts -- a hit resolves without reaching a `CertificateFactory`, so the provider only prices the miss. That is the whole reason the gain differs: `SUN` serves the no-cache baseline from its own certificate cache at this working set, and BouncyCastle has to parse.

**One thread, working set 512 (mostly misses):** the cache holds ~256, so this is the thrash case.

| Form | Provider | No cache | Cached | Gain |
| --- | --- | --- | --- | --- |
| Envoy `Cert=` PEM | `SUN` | **24.6 us** | 28.2 us | 0.87x |
| Envoy `Cert=` PEM | `BC` | **34.7 us** | 38.8 us | 0.89x |
| Gorouter raw base64 | `SUN` | **5.5 us** | 7.7 us | 0.71x |
| Gorouter raw base64 | `BC` | **14.5 us** | 17.3 us | 0.84x |
| CF app-identity | `SUN` | **2.5 us** | 3.3 us | 0.75x |
| CF app-identity | `BC` | **2.5 us** | 3.1 us | 0.79x |

## What the numbers support

- **The cache idea is sound; the key derivation is what costs.** Keyed by the header value, every
  form gets faster and allocates less: 8.2x for Envoy `Cert=`, 2.3x for raw base64, 4.6x for
  identity-only on the platform provider, and more on a provider without its own certificate cache.
  A SHA-256 digest of a 1.4-1.8 KB header costs more here than the parse it avoids.
- **`String.hashCode()` is the cheap hash.** About one cycle per byte against roughly ten for
  SHA-256 without hardware acceleration, and computed once per request either way -- the digest is
  pure addition on top.
- **Missing costs little with a raw key.** At 512 distinct certificates against ~256 slots the cache
  is overhead: 0.71x to 0.89x depending on form and provider, i.e. 12% to 40% slower than no cache.
  A digest key made this far worse, which is what ruled it out.
- **Identity-only headers only make sense to cache with a cheap key.** 2.1 us to 0.5 us with a raw
  key, where digesting the header would cost more than the field scan it saves.
- **Contention widens the gain.** At four threads the uncached path slows down while a cache hit
  does not, because the hit never takes the platform provider's cache monitor: raw base64 goes from
  2.3x to 3.5x, and on BouncyCastle from 6.2x to 6.4x.

## The JDK already caches parsed certificates

`CertificateFactory.generateCertificate()` consults `sun.security.provider.X509Factory.certCache` before parsing: 750 entries, soft references, keyed by the decoded DER bytes. In a heap dump of a filled cache, Eclipse MAT reports the immediate dominator of all 256 `X509CertImpl` objects as `<ROOT>` -- each is owned both by this filter's cache and by the JDK's:

```
sun.security.util.MemoryCache  entries=256  maxSize=750  retained=30,944
```

**A small working set understates the parse.** Below 750 distinct certificates the no-cache variant is served by the JDK cache too, so it never pays a cold ASN.1 parse. Pushing past 750, with this filter's cache sized to hold the working set (`RAW_BASE64`, one thread, `cacheSize=1024`):

| Distinct certificates | JDK cert cache | No cache | This filter's cache |
| --- | --- | --- | --- |
| 100 | covers the working set | 5.2 us / 9304 B | 2.4 us / 1456 B |
| 2000 | thrashes at 750 | **16.1 us / 28536 B** | **2.7 us / 1456 B** |

A cold parse costs 16.1 us and ~28 KB allocated per call, not the 5.2 us and ~9 KB a warm JDK cache suggests. This filter's cache stays near 2.5 us either way, so its advantage grows from 2.2x to 6.0x (6.4x to 19.6x on allocation) exactly where deployments have many distinct callers.

**What this filter's cache adds.** The JDK cache helps only when the same DER repeats within 750 entries, and is keyed on the *decoded* bytes, so the base64 or URL-decode happens before the lookup can. It does nothing for the `XfccEntry` field scan, the Subject DN parse or the `Cert=` extraction, and being soft-referenced and JVM-wide it is shared with everything else doing X.509 work and dropped under memory pressure.

## The JVM's certificate cache serializes every lookup

`X509Factory` reaches its cache through `static synchronized` helpers (`getFromCache`/`addToCache`), which lock the `X509Factory` class object, so every certificate parse in the JVM queues on a single monitor whether or not it hits that cache.

This is not a new observation. [JDK-6432000][jdk-6432000], filed in 2006 at P2, says it directly -- "the certificate cache in sun.security.provider.X509Factory can limit scalability if there are many threads parsing many certificates concurrently" -- and weighs three fixes: a cache framework, `ReadWriteLock`s or batch expunging, or FIFO replacement via `ConcurrentHashMap`. It was closed as *Not an Issue*. Its duplicate [JDK-6440092][jdk-6440092] adds that the cache sits "right in the critical path of `engineGenerateCertificate()`" even for callers holding their own factory instance.

**It was narrowed twenty years later, not removed.** [JDK-8345954][jdk-8345954] -- titled for `X509TrustManagerImpl`, but its patch touches only `X509Factory` -- was integrated on 2026-03-30 for JDK 27. Both `intern` overloads, `getFromCache` and `addToCache` lose `static synchronized`, and the certificate is built *outside* any lock; what remains is `synchronized (cache)` around check-and-insert. But `sun.security.util.MemoryCache.get` and `put` are themselves `synchronized` methods, in JDK 27 exactly as in 25, so **every lookup still serializes** -- on the cache instance rather than the `X509Factory` class. What moved out of the lock is the parse, which is why the fix shows up on misses and barely at all on hits. [JDK-8380421][jdk-8380421], opened out of that work, proposes eager hash initialization in the `Cache.EqualByteArray` key type both caches use.

Measured with `ParseLockProbe` (plain threads, no JMH, 6-second runs), same machine, Liberica JDK 25.0.2 and 27+36:

| Provider | Working set | JDK | 1 thread | 4 threads | Scaling |
| --- | --- | --- | --- | --- | --- |
| `SUN` | 16 (cache hits) | 25 | 369,018/s | 507,990/s | **1.38x** |
| `SUN` | 16 (cache hits) | 27 | 364,245/s | 544,124/s | **1.49x** |
| `SUN` | 2000 (cache misses) | 25 | 69,026/s | 207,586/s | 3.01x |
| `SUN` | 2000 (cache misses) | 27 | 67,439/s | 220,831/s | 3.27x |
| BouncyCastle | 16 | 25 | 84,057/s | 242,800/s | 2.89x |
| BouncyCastle | 16 | 27 | 83,949/s | 257,459/s | 3.07x |
| BouncyCastle | 2000 | 25 | 76,730/s | 258,613/s | 3.37x |
| BouncyCastle | 2000 | 27 | 70,769/s | 254,254/s | 3.59x |

Read the scaling column. Four cores return `SUN` about 1.4x on the hit path, where BouncyCastle returns ~2.9x and neither reaches the 4x the hardware could give. The gap is the cache lock: per-thread latency on `SUN` goes from 2.7 us to 7.9 us as soon as four threads contend for it. JDK 27 is measurably better on both paths -- 1.38x to 1.49x on hits, 3.01x to 3.27x on misses -- which is the parse having left the lock.

**An earlier revision of this document reported `SUN` scaling at 0.71x and 0.74x -- throughput *below* single-threaded. That was a measurement artefact.** With Turbo Boost enabled, a single-threaded run clocks to 3.3 GHz while a four-thread run throttles under it, so the ratio is computed between two different clock speeds. Pinning the clock at 2.3 GHz removes the illusion: the same hardware measures 1.38x. The contention is real -- it costs most of what four cores could give, and the blocked-time figures below show why -- but it never ran backwards.

Which providers can be named, and how to select one, is in [PROVIDERS.md](PROVIDERS.md). BouncyCastle FIPS was measured at the same rate as the regular distribution in an earlier round, with the provider added to the classpath by hand; it is not re-verified here, and this module depends on neither. The Amazon Corretto Crypto Provider registers no `CertificateFactory` at all; naming it (or any provider lacking X.509) makes `getInstance` throw `CertificateException`, which the filter catches and degrades to the platform default. BouncyCastle and BouncyCastle FIPS cannot share a classpath -- both populate `org.bouncycastle.*` with different jar signers, so loading the second throws `SecurityException: ... signer information does not match`, which is why this library ships no BouncyCastle of its own.

JFR with `jdk.JavaMonitorEnter#threshold=0ms`, four threads, 16 distinct certificates, 6-second runs:

| Provider | JDK | Blocked events | Total blocked time |
| --- | --- | --- | --- |
| `SUN` | 25 | 27,896 | 11,113 ms of ~24 thread-seconds (**46%**) |
| `SUN` | 27 | 27,642 | 11,202 ms (**47%**) |
| BouncyCastle | 25 | 38 | 15 ms |
| BouncyCastle | 27 | 33 | 20 ms |

The blocked time is the same on both releases, which is the clearest statement of what JDK-8345954 did and did not change: the lock moved, the serialization did not.

The blocking site is explicit in the recorded stacks:

```
monitorClass = java.lang.Class (classLoader = bootstrap)
  sun.security.provider.X509Factory.getFromCache(Cache, byte[]) line: 224
  sun.security.provider.X509Factory.cachedGetX509Cert(byte[]) line: 109
  sun.security.provider.X509Factory.engineGenerateCertificate(InputStream) line: 97
  java.security.cert.CertificateFactory.generateCertificate(InputStream) line: 355
```

Line 224 in that stack is the declaration of `private static synchronized <K,V> V getFromCache` in the JDK 25 source (`lib/src.zip`), which is what makes every lookup take the class monitor. On JDK 27 the same file declares no `static synchronized` method at all -- one `synchronized (cache)` block remains, around check-and-insert.

The default JFR threshold for `jdk.JavaMonitorEnter` is 20 ms, which hides these entirely -- the stalls are microseconds each and only their number matters. Measure at threshold zero, outside JMH: the harness's own state-init monitor otherwise dominates the recording.

Per-parse cost by provider (one thread, `ParseProviderBenchmark`):

| Working set | `SUN` | BouncyCastle |
| --- | --- | --- |
| 16 distinct (JDK cache hits) | 2.6 us | 10.7 us |
| 2000 distinct (JDK cache misses) | 12.3 us | 11.0 us |

BouncyCastle is slower in isolation but immune to both the cache's limits and its lock, so the combination that avoids the monitor is this filter's cache for hits plus a lock-free provider for misses.

The filter resolves its `CertificateFactory` with no provider name, so provider order alone can select BouncyCastle. Verified on JDK 21:

| Registration | `CertificateFactory.getInstance("X.509").getProvider()` |
| --- | --- |
| stock JVM | `SUN` |
| `Security.addProvider(new BouncyCastleProvider())` | `SUN` (BC appended at position 13) |
| `Security.insertProviderAt(new BouncyCastleProvider(), 1)` | `BC` |
| `getInstance("X.509", "SUN")` with BC at position 1 | `SUN` |

Check the third row before believing an application is on BouncyCastle: `addProvider` appends, so the usual idiom leaves parsing on `SUN` and its monitor. The fourth is why `org.cloudfoundry.router.certificate.provider` works in both directions -- naming a provider overrides order, so the filter can be pinned to `SUN` inside a JVM that put BC first.

### Clearing the JVM cache

`CertificateFactory.generateCertificate(null)` clears `X509Factory`'s cache and throws `CertificateException("Missing input stream")` -- labelled "for debugging" in the JDK source. Useful to force cold-parse measurements, verified by object identity: a repeat parse returns the same instance before the clear, a different one after. Not for production -- it wipes a JVM-wide cache other components rely on. [JDK-8059007][jdk-8059007], open since 2014, is a report of exactly this being used in anger: with `crlCache` holding 750 entries of roughly 1 MB each, a deployment reissuing CRLs every two hours purged it hourly through that internal call, and asked for a configurable size or a public management API. Neither exists yet, for either cache.

## Cache key: digest vs raw value

`CacheKeyBenchmark` isolates the key strategy, looking up a pre-populated map from a freshly built `String`:

| Key strategy | 1.3 KB header (us) | 2.4 KB header (us) | B/op at 1.3 KB |
| --- | --- | --- | --- |
| SHA-256 hex digest | 13.1 | 23.2 | 3392 |
| Raw header value | **2.0** | **3.6** | **1344** |

The raw value is the faster key here by ~6.6x at 1.3 KB and ~6.4x at 2.4 KB, because `String.hashCode()` costs about one cycle per byte where SHA-256 costs about ten on a CPU without the SHA extensions. With them the digest gets much cheaper; this machine cannot measure by how much. **An earlier version of this document claimed the digest key was ~14.6x faster; that does not reproduce and has been removed** -- it likely computed the digest outside the timed region, charging that strategy nothing for work the request path performs every call.

The digest key's remaining advantage is memory: a 64-character key against a value key retaining the whole header, roughly 1.4-1.8 KB per entry for CF-shaped headers and more where `maxHttpHeaderSize` was raised. The filter pays that for the speed, bounded by `cache.size`. A value key also removes the collision question -- `equals()` confirms every hit -- at the cost of being the caller-supplied string, which `ConcurrentHashMap` handles by treeifying degenerate buckets.

## Memory

Two generations of up to `cache.size` entries each (128 by default). Measured on JDK 21 with a full cache of 256 CF-shaped entries, by three methods that answer different questions:

| Form | Header | Key only (JOL) | Entry (JOL graph) | Exclusively retained (MAT) |
| --- | --- | --- | --- | --- |
| Envoy `Cert=` PEM | 1847 B | 1938 B | 10632 B | -- |
| Gorouter raw base64 | 1416 B | 1496 B | 7802 B | 1545 B* |
| CF app-identity | 262 B | 344 B | 1152 B | -- |

\* The MAT column is from an earlier round on a machine with Eclipse MAT installed; it was not re-measured here, unlike the JOL columns. Reproduce it with the heap-dump recipe below.

JOL walks everything reachable from the cache; MAT reports the retained heap of the `CertificateCache` instance, only what would be freed if the cache went away, and is four times smaller because the certificates are co-owned by the JDK cert cache above. The cost therefore depends on whether the JDK is also holding the certificate:

- **Within the JDK cache's reach (<=750 distinct certificates):** ~1.5 KB per entry, ~0.4 MB for a
  full 256-entry cache. The certificate is shared; this cache adds the key string, the map node and
  the `ParsedXfcc`/`XfccEntry` shells.
- **Beyond it, or after soft references are cleared under memory pressure:** this cache is the sole
  owner and carries the whole ~7.8 KB (raw base64) or ~10.6 KB (Envoy PEM) per entry -- measured by
  JOL at 1950 KB and 2658 KB respectively for a full 256-entry cache, and 288 KB for identity-only
  entries.

A parsed `X509Certificate` is **6.1x its DER** (1061 B DER, 6520 B object graph), which is why the entry dwarfs the key: keying on the header value rather than a 64-character digest added roughly 20% to a full cache, not 2x. The honest framing: this cache converts soft-reclaimable memory the collector may drop under pressure into strongly-held memory it may not.

The rough sizing bound is `2 x cache.size x (header bytes + parsed certificate)`. Apps that raised `maxHttpHeaderSize` scale both terms and should lower `cache.size`; apps serving more distinct callers than `2 x cache.size` should raise it, since the cold-parse numbers above are what a miss costs.

### Reproducing the memory figures

```shell
# object-graph sizes per header form (JDK 21 or older; JOL cannot walk some JDK 25 internals)
$ ./mvnw -Pbenchmarks -DskipTests package
$ java -cp java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar \
       org.cloudfoundry.router.benchmark.CacheFootprint

# retained heap, the authoritative figure: dump a running app and query it headlessly
$ jcmd <pid> GC.heap_dump /tmp/app.hprof
$ ParseHeapDump.sh /tmp/app.hprof \
      -command="oql \"SELECT x, x.@retainedHeapSize FROM org.cloudfoundry.router.CertificateCache x\"" \
      org.eclipse.mat.api:query
```

## Header hiding

Hiding the header (`org.cloudfoundry.router.certificate.header.hide`) keeps large base64 certificate values out of downstream filters that iterate or log all headers. Measured separately from the JMH runs, with a Spring Boot app behind `CommonsRequestLoggingFilter` and the raw XFCC header as forwarded by CF Gorouter; `byte[]` allocation captured via JFR over a 40-second run at 500 requests/second:

| `header.hide` | `cache.enabled` | Request logging filter | `byte[]` allocation |
|---|---|---|---|
| `false` | `false` | enabled | 1.47 GiB |
| `true` | `false` | enabled | 791 MB |
| `true` | `true` | enabled | 547 MB |
| `true` | `true` | disabled | 60.5 MB |

The dominant cost is the `byte[]` allocation inside the logging filter itself: hiding the header removes most of it, caching removes the repeated certificate parsing on top. This run predates the JMH module and its environment is not recorded beyond the settings above.

Hiding does not free the header string during the request -- it stops downstream code reading it; memory is reclaimed when the request completes. The wrapper is created only when the header is present, so requests without a client certificate carry no overhead.

[jdk-6432000]: https://bugs.openjdk.org/browse/JDK-6432000
[jdk-6440092]: https://bugs.openjdk.org/browse/JDK-6440092
[jdk-8059007]: https://bugs.openjdk.org/browse/JDK-8059007
[jdk-8179389]: https://bugs.openjdk.org/browse/JDK-8179389
[jdk-8345954]: https://bugs.openjdk.org/browse/JDK-8345954
[jdk-8380421]: https://bugs.openjdk.org/browse/JDK-8380421
