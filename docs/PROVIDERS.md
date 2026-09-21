# Certificate parsing providers

Which JCA provider parses the certificates in `X-Forwarded-Client-Cert`, how to change it, and what
the measurements say. This matters only for applications that see many distinct client certificates
under real concurrency.

## The default

The filter calls `CertificateFactory.getInstance("X.509")` with **no** provider name, so the JCA
picks the first registered provider offering that service. On a stock JVM that is `SUN`.

`SUN` parses through `sun.security.provider.X509Factory`, which keeps a 750-entry soft-referenced
certificate cache keyed by the DER bytes and reaches it through `static synchronized` helpers. Every
`generateCertificate()` call in the JVM therefore serializes on the `X509Factory` class monitor,
hit or miss. Measured on four threads with 16 distinct certificates: ~46% of thread time blocked,
and four cores return 1.4x the throughput of one rather than the 4x the hardware could give,
because per-thread latency rises from 2.7 us to 7.9 us. Reported against the JDK in 2006 as
[JDK-6432000](https://bugs.openjdk.org/browse/JDK-6432000), closed as *Not an Issue*, and narrowed
-- not removed -- for JDK 27 by [JDK-8345954](https://bugs.openjdk.org/browse/JDK-8345954): the
parse moved out of the lock, but `MemoryCache.get`/`put` stay `synchronized`, and measured blocked
time is identical on JDK 25 and 27. Recordings and stacks are in [PERFORMANCE.md](PERFORMANCE.md).

## Changing it implicitly, by provider order

Whatever sits first in the JVM's provider list wins. Verified on JDK 21:

| How the application registers BouncyCastle | Provider the filter uses |
| --- | --- |
| `Security.addProvider(new BouncyCastleProvider())` | **`SUN`** -- BouncyCastle is *appended last* |
| `Security.insertProviderAt(new BouncyCastleProvider(), 1)` | `BC` |
| `java.security` entries, or `-Djava.security.properties=...`, listing BC first | `BC` |

**Mind the `addProvider` trap.** `addProvider` appends (position 13 on a stock JDK 21), so the common
registration idiom leaves certificate parsing on `SUN` and on its monitor while appearing to "have
BouncyCastle". Only `insertProviderAt(..., 1)` or a `java.security` change moves it ahead. Changing
provider order is JVM-wide: every library's X.509, TLS and signature work moves with it.

## Changing it explicitly, for this filter only

```
-Dorg.cloudfoundry.router.certificate.provider=BC
```

The filter then parses through that provider while the rest of the JVM keeps its usual one. A named
provider overrides provider order in both directions, so a JVM that moved BouncyCastle to the front
can still pin this filter back with `...provider=SUN`.

**This filter never registers a provider itself**, so nothing about the JVM's security configuration
changes because it is present. Two failure modes degrade to the platform default with a warning
rather than failing startup: the named provider is not registered (`NoSuchProviderException`), or it
offers no X.509 factory (`CertificateException`). The effective provider is logged at `INFO`.

## Which providers can be named

On a stock JDK 21 exactly one built-in provider offers an X.509 `CertificateFactory` -- `SUN` -- so
alternatives must come from the application. Measured with `ParseLockProbe`, 6-second runs, parses
per second at 1 and 4 threads on a 4-core machine:

| Provider | Offers X.509 | 16 certs, 1t / 4t | 2000 certs, 1t / 4t |
| --- | --- | --- | --- |
| `SUN` (built in) | yes | 369,018 / 507,990 | 69,026 / 207,586 |
| BouncyCastle (`BC`) | yes | 84,057 / 242,800 | 76,730 / **258,613** |
| BouncyCastle FIPS (`BCFIPS`) | yes | not re-measured -- see below | |
| Amazon Corretto Crypto Provider | **no** | -- | -- |

- **`SUN`** is fastest whenever certificates repeat within its 750-entry cache (2.6 us per hit) but
  scales poorly: four threads return 1.4x, not 4x, because every lookup takes the cache monitor.
- **BouncyCastle** is ~4x slower per parse in isolation, yet has no cache to lock, so four threads
  return ~2.9x and it overtakes `SUN` on workloads that miss the JVM cache.
- **BouncyCastle FIPS** measured at the same rate as the regular distribution in an earlier round,
  with the provider put on the classpath by hand; the figures above do not cover it. Note `bc-fips`
  and `bcprov` cannot share a classpath: both populate `org.bouncycastle.*` with different jar
  signers, and loading the second throws `SecurityException: ... signer information does not match`.
  That is also why this library ships no BouncyCastle of its own.
- **Amazon Corretto Crypto Provider** registers no X.509 `CertificateFactory` at all -- it
  accelerates ciphers, digests and signatures. Any provider lacking that service behaves the same
  way here: `getInstance` throws `CertificateException`, which the filter logs before falling back
  to the platform default.

## When to bother

Switch providers only when both hold:

1. the application sees more distinct client certificates than the JVM cache holds (750), so parses
   actually happen, and
2. requests arrive concurrently enough for the monitor to matter.

For a handful of repeating callers, leave it alone -- a `SUN` cache hit costs 2.6 us against
BouncyCastle's 10.7 us.

All of this concerns the *miss* path. With this filter's own cache enabled and sized to the caller
population, a hit resolves in ~2.3 us without touching any provider, JVM cache or monitor. Provider
choice only decides what a miss costs.

### On JDK 27 and later

[JDK-8345954](https://bugs.openjdk.org/browse/JDK-8345954) narrows the lock rather than removing it:
the certificate is parsed outside it, and what remains guards check-and-insert on the cache instance
instead of the `X509Factory` class. Measured, that helps misses (`SUN` scaling 2.73x to 3.00x at
2000 distinct certificates) and leaves hits alone -- blocked time at four threads is 11,327 ms on
JDK 25 and 11,328 ms on JDK 27, because `MemoryCache.get` and `put` remain `synchronized`.

Mind which releases it reaches, too. JDK 27 is not an LTS: GA 15 September 2026, six-month window,
JDK 28 follows in March 2027. **A deployment tracking LTS goes from JDK 25 straight to JDK 29 in
September 2027**, so for the Cloud Foundry buildpacks this stays live for about another year.

The reasons to name a provider are therefore unchanged in substance:

- **The JDK cache still holds 750 entries, soft-referenced, keyed on the decoded DER.** Past that
  the platform provider parses cold on every miss -- 12.3 us against BouncyCastle's flat 11.0 us --
  and the entries can be dropped under memory pressure whether or not they would have been reused.
  Deployments serving more distinct callers than that still measure the two providers differently.
- **The narrowed lock is not no lock.** Check-and-insert still runs under `synchronized (cache)`, so
  map operations serialize; what moved outside is the parse. A provider with no cache has neither.
- **Pinning back to the platform default.** Provider order is JVM-wide, so an application that calls
  `Security.insertProviderAt(new BouncyCastleProvider(), 1)` moves *everything* to BouncyCastle.
  Naming `SUN` here returns this filter to the platform provider without touching that order.
- **FIPS.** `BCFIPS` is a policy requirement where it applies, not a performance choice, and it
  parses at the same rate as the regular distribution.

With this filter's own cache enabled and sized to the caller population, none of this is on the hot
path: a hit resolves without reaching a `CertificateFactory` at all.

## Hardware-backed providers

Not applicable. The filter performs no cryptographic operations: parsing an X.509 certificate is
ASN.1 decoding, and the filter never verifies a signature or touches a private key. PKCS#11 tokens
and HSMs protect private keys, and BouncyCastle's native extensions accelerate AES and SHA; neither
applies to certificate parsing. Hardware-backed crypto belongs at the proxy terminating mTLS, at an
application making outbound mTLS calls, or at the CA issuing the certificates.
