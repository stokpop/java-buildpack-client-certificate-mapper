/*
 * Copyright 2017-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.router;

import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A bounded, lock-free certificate cache based on a generational eviction strategy.
 *
 * <p>Two generations of {@link ConcurrentHashMap} are maintained: {@code currentGen} and
 * {@code prevGen}. Lookups check current first, then previous. When the current generation
 * reaches {@code maxGenSize}, it is promoted to previous (the old previous is discarded) and
 * a fresh current generation starts. This keeps memory bounded at approximately
 * {@code 2 * maxGenSize} entries while avoiding any locking on the read path.
 *
 * <p><b>Why not key by the raw certificate string.</b> Using the full ~1.3 KB {@code Cert=} (or raw
 * header) value directly as the map key was measured to burn most of the cache's benefit: because
 * each request produces a fresh {@code String} instance from XFCC substring parsing,
 * {@link String#hashCode()} cannot be reused across requests and traverses the whole key on every
 * lookup, and a hit also requires a full-length {@link String#equals(Object)}. JMH measurement on
 * JDK 25 (single-threaded, {@code AverageTime}, 5+5 iterations × 2 forks):
 * <pre>
 *   parse the cert every call (no cache):            ~3620 ns/op
 *   cache hit keyed by the raw ~1.3 KB cert string:  ~1890 ns/op  (only 1.9x vs no cache)
 *   cache hit keyed by 64-char SHA-256 hex digest:    ~130 ns/op  (28x vs no cache)
 * </pre>
 * Deriving a short digest recovers ~14.6x of the per-hit cost and — under real concurrent load —
 * removes the compounded per-request CPU that made a raw-key cache measurably worse than no cache
 * at all in field measurements.
 *
 * <p><b>Memory budget.</b> Keys are 64-character SHA-256 hex digests derived from the certificate
 * bytes (either the XFCC {@code Cert=} field value or, for non-XFCC requests, the full raw header
 * value). Deriving the key ensures only a request carrying the actual certificate can produce a
 * hit, and keeps {@link String#hashCode()} and {@link String#equals(Object)} on the cache key cheap
 * on every lookup. Note that the digest is taken over the header string as received — the
 * URL-encoded PEM or base64 DER — not over the decoded DER bytes, so the key intentionally differs
 * from the Envoy XFCC {@code Hash=} field (which is defined as SHA-256 of the DER). This is fine
 * for cache identity (same header value produces the same key) but means the two hashes are not
 * cross-comparable. With the default generation size of 128, the cache holds at most ~256
 * {@code X509Certificate} objects plus ~16 KB of key strings. If this is a concern, disable caching
 * via the {@code org.cloudfoundry.router.certificate.cache.enabled} system property.
 *
 * <p><b>Security note.</b> Cached entries are not expiry-checked on retrieval. The filter
 * does not validate certificate validity on cache hits (nor on misses), consistent with
 * behaviour before caching was introduced. Callers that require expiry enforcement should
 * check {@code X509Certificate.checkValidity()} on the mapped attribute themselves.
 *
 * <p>The implementation is safe for concurrent use. Under a simultaneous rotation race,
 * at most a few entries may be re-parsed once — no data is corrupted.
 *
 * <p><b>Logging.</b> Every lookup logs a hit or a miss at {@code FINE}. Generation rotation logs
 * a {@link #statistics() statistics} snapshot: the first rotation at {@code INFO}, because that is
 * the point at which the cache reaches capacity and starts evicting, and every rotation after it at
 * {@code FINE}, so traffic with mostly unique certificates cannot flood the log. Rotation is used as
 * the reporting interval because it needs no timer and no clock reads on the request path.
 *
 * <p>Use {@link #get(String)} and {@link #put(String, X509Certificate)} as the only entry
 * points so the implementation can be replaced without touching call sites.
 */
public final class CertificateCache {

    private static final Logger LOGGER = Logger.getLogger(CertificateCache.class.getName());

    private final int maxGenSize;

    private final LongAdder hits = new LongAdder();

    private final LongAdder misses = new LongAdder();

    private final LongAdder rotations = new LongAdder();

    /** Guards the one-off {@code INFO} log for the rotation that first takes the cache to capacity. */
    private final AtomicBoolean capacityReached = new AtomicBoolean();

    private volatile ConcurrentHashMap<String, X509Certificate> currentGen;
    private volatile ConcurrentHashMap<String, X509Certificate> prevGen;

    public CertificateCache(int maxGenSize) {
        this.maxGenSize = maxGenSize;
        this.currentGen = new ConcurrentHashMap<>();
        this.prevGen = new ConcurrentHashMap<>();
    }

    /** Returns the cached certificate for {@code key}, or {@code null} if not present. */
    public X509Certificate get(String key) {
        X509Certificate cert = currentGen.get(key);
        if (cert == null) {
            cert = prevGen.get(key);
        }
        if (cert == null) {
            this.misses.increment();
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Certificate cache miss; the certificate will be parsed");
            }
            return null;
        }
        this.hits.increment();
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Certificate cache hit; skipping certificate parsing");
        }
        return cert;
    }

    /** Stores {@code cert} under {@code key}, rotating generations if the current one is full. */
    public void put(String key, X509Certificate cert) {
        if (currentGen.size() >= maxGenSize) {
            prevGen = currentGen;
            currentGen = new ConcurrentHashMap<>();
            this.rotations.increment();
            logRotation();
        }
        currentGen.put(key, cert);
    }

    /** Returns the number of lookups that were served from the cache. */
    public long getHitCount() {
        return this.hits.sum();
    }

    /** Returns the number of lookups that required the certificate to be parsed. */
    public long getMissCount() {
        return this.misses.sum();
    }

    /** Returns the number of generation rotations performed so far. */
    public long getRotationCount() {
        return this.rotations.sum();
    }

    /** Returns a snapshot of the cache counters, suitable for logging. */
    public String statistics() {
        long hitCount = this.hits.sum();
        long missCount = this.misses.sum();
        long lookups = hitCount + missCount;
        long hitRate = lookups == 0 ? 0 : (hitCount * 100) / lookups;
        return "rotations=" + this.rotations.sum() + ", hits=" + hitCount + ", misses=" + missCount
            + ", hit rate=" + hitRate + "%, capacity=" + (2 * this.maxGenSize) + " certificates";
    }

    private void logRotation() {
        // The first rotation is the moment the cache fills up and starts evicting, so report it once at INFO
        // where operators will see it without turning on FINE. Later rotations are routine and stay at FINE:
        // traffic with mostly unique certificates rotates every maxGenSize misses and would flood the log.
        boolean first = this.capacityReached.compareAndSet(false, true);
        if (!first && !LOGGER.isLoggable(Level.FINE)) {
            return;
        }
        String message = "Certificate cache rotated a generation (" + statistics()
            + "). A low hit rate means the working set of certificates exceeds the cache size; raise"
            + " org.cloudfoundry.router.certificate.cache.size to retain more of them.";
        if (first) {
            LOGGER.info(message);
        } else {
            LOGGER.fine(message);
        }
    }
}
