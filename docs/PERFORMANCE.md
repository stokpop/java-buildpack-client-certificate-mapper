# Performance notes

Background for the caching and header-hiding settings documented in the [README](../README.md#configuration). Nothing here is needed to use the filter.

## Certificate cache

Parsed results are cached and reused across requests for the same header entry, avoiding a repeated DER/PEM parse. Caching is on by default (`org.cloudfoundry.router.certificate.cache.enabled`).

**Every entry is cached, including identity-only ones.** The cache exists mainly to amortise the expensive ASN.1 parse of an actual certificate, but since a SHA-256 digest of the raw header is computed and checked against the cache before it is known whether the entry carries a certificate, the parsed result is stored on a miss regardless -- including identity-only XFCC headers that carry just `Hash=`/`Subject=` (e.g. the CF app-identity headers on an mTLS domain) and unsupported `Chain=`-only entries. A repeat of one of these skips the field-map parse too, at negligible extra memory cost since there is no certificate to hold.

**Multiple headers vs. a certificate chain.** A request can carry multiple `X-Forwarded-Client-Cert` entries -- as separate header lines or comma-joined in one line -- typically from multiple hops each terminating their own mTLS connection and appending their own entry. Each entry is a **separate leaf certificate**, cached **independently** under its own SHA-256 key; a cache hit or miss on one entry never affects another, and the mapped `X509Certificate[]` attribute preserves header order regardless of cache state. This is unrelated to a single certificate's **trust chain** (the XFCC `Chain=` field, carrying intermediate CA certificates for one leaf cert) -- that field is not supported for certificate mapping: an entry with `Chain=` but no `Cert=` maps no certificate, but its parsed result is still cached like every other entry.

## Cache key

The cache key is a 64-character SHA-256 hex digest of the header entry as received -- not the raw string itself, and not the router-supplied `Hash=` field, which external clients could inject when header stripping is disabled. Only a request carrying the byte-for-byte same header value can produce a cache hit. The digest is taken over the header string as received (URL-encoded PEM or base64 DER), not over the decoded DER bytes, so it intentionally differs from the Envoy XFCC `Hash=` field (SHA-256 of the DER) and the two are not cross-comparable.

**Why a short derived key rather than the raw certificate string.** Using the full ~1.3 KB `Cert=` value directly as the map key was measured to burn most of the cache's benefit: a hit still needs a full-length `String.equals()`, and hashing the whole key on every lookup. `String` caches its computed hash in a private field after the first call, but each request produces a fresh `String` from XFCC substring parsing -- a new object that has never computed that hash -- so the per-object cache never carries over between requests even though the hash value itself is identical for identical content.

JMH on JDK 25 (single-threaded, average time, 5+5 iterations x 2 forks) using a typical ~1.3 KB CF app-identity certificate:

| Strategy | ns/op | vs. no cache |
| --- | --- | --- |
| Parse the cert every call (no cache) | ~3620 | 1x (baseline) |
| Cache hit keyed by raw ~1.3 KB cert string | ~1890 | 1.9x faster |
| Cache hit keyed by 64-char SHA-256 hex digest | **~130** | **28x faster** |

The short digest recovers ~14.6x of the per-hit cost. Under real concurrent load this compounded per-request CPU is what previously made a raw-key cache measurably worse than no cache at all.

## Memory

The cache uses a generational eviction strategy (two generations of up to 128 entries each, configurable via `org.cloudfoundry.router.certificate.cache.size`). The cache **keys** are cheap: 64-character SHA-256 hex digests, ~16 KB total across 256 entries. The memory comes from the cached **values** -- each is a `ParsedXfcc` bundle holding the parsed `X509Certificate` plus the `XfccEntry` it was derived from, which retains the raw `Cert=` substring (typically 1-2 KB). With both generations full (~256 entries), that is a worst-case total of roughly **~1.5 MB**.

## Header hiding

Hiding the header (`org.cloudfoundry.router.certificate.header.hide`) keeps large base64 certificate values out of downstream filters that iterate or log all headers. Measured with a Spring Boot app behind `CommonsRequestLoggingFilter` (which reads and logs all request headers on every request), with the raw XFCC header as forwarded by CF Gorouter. `byte[]` allocation captured via Java Flight Recorder over a 40-second run at 500 requests/second:

| `header.hide` | `cache.enabled` | Request logging filter | `byte[]` allocation |
|---|---|---|---|
| `false` | `false` | enabled | 1.47 GiB |
| `true` | `false` | enabled | 791 MB |
| `true` | `true` | enabled | 547 MB |
| `true` | `true` | disabled | 60.5 MB |

The largest impact by far is the `byte[]` allocations inside the logging filter itself -- hiding the header is what removes most of them; caching removes the remaining repeated certificate parsing on top of that.

Hiding the header does not free the underlying string memory during the request -- it prevents downstream code from reading it. Memory is reclaimed when the request completes and the original request object is GC'd. The wrapper is only created when the header is actually present, so there is no overhead for requests without a client certificate.
