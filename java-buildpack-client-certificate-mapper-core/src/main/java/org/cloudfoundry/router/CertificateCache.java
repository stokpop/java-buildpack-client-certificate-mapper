/*
 * Copyright 2017-2026 the original author or authors.
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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A bounded, lock-free cache of {@link ParsedXfcc} bundles based on a generational eviction strategy.
 *
 * <p>Two generations of {@link ConcurrentHashMap} are maintained: {@code currentGen} and
 * {@code prevGen}. Lookups check current first, then previous. When the current generation
 * reaches {@code maxGenSize}, it is promoted to previous (the old previous is discarded) and
 * a fresh current generation starts. This keeps memory bounded at approximately
 * {@code 2 * maxGenSize} entries while avoiding any locking on the read path. The bound is not
 * exact: a generation is checked for room before an insert, so threads missing at the same moment
 * can each add one entry past {@code maxGenSize}.
 *
 * <p><b>What is cached.</b> The cache value is a {@link ParsedXfcc} bundle: the parsed
 * {@link XfccEntry}, the decoded {@link java.security.cert.X509Certificate}, and, when present,
 * the parsed {@link CfSubjectDn}. Caching the full bundle rather than only the certificate lets a
 * repeat of the same header skip {@code XfccEntry} one-pass parsing (~1.3 KB scan per request) and
 * CF subject DN parsing, both of which showed up in profiler traces even after X.509 parsing was
 * already being cached.
 *
 * <p><b>Concurrent misses.</b> {@link #getOrCompute(String, ParsedXfccSupplier)} parses outside
 * any map lock and publishes the result with {@link ConcurrentHashMap#putIfAbsent}. Threads that miss
 * on the same cache-cold key at the same moment each parse it; the first result stored wins and
 * every caller receives that one instance. The extra parses are the price of never holding a lock
 * while parsing: {@code computeIfAbsent} would deduplicate them, but it runs the parse under the
 * hash-bin lock, so a client that controls the header could pick values with colliding hash codes
 * and have their misses parsed one at a time. Prefer {@code getOrCompute} over the raw
 * {@link #get} / {@link #put} pair on hot paths.
 *
 * <p><b>Why the header value is the key.</b> Keys are the raw {@code X-Forwarded-Client-Cert}
 * entry exactly as received. Each request produces a fresh {@code String} from header parsing, so
 * {@link String#hashCode()} is computed once per lookup, traversing the value at roughly one cycle
 * per byte, and a hit is confirmed by a full {@link String#equals(Object)}. Deriving a SHA-256
 * digest to use as a shorter key was measured to cost more than it saves: the digest traverses the
 * same bytes at roughly ten cycles per byte on hardware without SHA extensions, which exceeds the
 * certificate parse the cache exists to avoid. JMH, single thread, working set of 16, platform
 * provider, no SHA hardware acceleration (see {@code docs/PERFORMANCE.md} for the full matrix and
 * the measurement setup):
 * <pre>
 *   Envoy Cert= PEM,     no cache / cached:  24.3 / 3.0 us
 *   Gorouter raw base64, no cache / cached:   5.2 / 2.3 us
 *   CF app-identity,     no cache / cached:   2.1 / 0.5 us
 * </pre>
 * Keying on a SHA-256 digest instead was measured at 13.0 us against 2.0 us for the raw value on a
 * 1.3 KB header ({@code CacheKeyBenchmark}), which is why that design was dropped.
 * Keying on the value also removes the question of key collisions entirely: two different headers
 * cannot map to one cached certificate, because {@code equals} decides every hit.
 *
 * <p><b>Memory budget.</b> A key is the header string itself -- typically 1.4-1.8 KB for CF-shaped
 * headers, and as large as the container's {@code maxHttpHeaderSize} allows where that limit has
 * been raised for certificates with long chains. Each value is a {@link ParsedXfcc} holding the
 * parsed {@link java.security.cert.X509Certificate} and the {@link XfccEntry} it came from, which
 * retains the recognised field values. Measured on JDK 21 with 256 CF-shaped entries: ~7.8 KB per
 * entry reachable (raw base64) or ~10.6 KB (Envoy PEM), of which only ~1.5 KB is retained
 * exclusively by this cache -- the rest is shared with the JVM's own parsed-certificate cache
 * ({@code sun.security.provider.X509Factory}, 750 soft-referenced entries). Beyond that cache's
 * reach, or once its soft references are cleared, this cache owns the full amount, so the bound is
 * {@code 2 x size x (header bytes + parsed certificate)}: ~0.4 MB to ~2 MB at the default size for
 * CF-shaped headers. Size the cache with {@code org.cloudfoundry.router.certificate.cache.size}, or
 * disable it entirely via {@code org.cloudfoundry.router.certificate.cache.enabled}.
 *
 * <p><b>Security note.</b> Cached entries are not expiry-checked on retrieval. The filter
 * does not validate certificate validity on cache hits (nor on misses), consistent with
 * behaviour before caching was introduced. Callers that require expiry enforcement should
 * check {@code X509Certificate.checkValidity()} on the mapped attribute themselves.
 *
 * <p>The implementation is safe for concurrent use. Reads ({@link #get}, {@link #peek}) and cache
 * hits on {@link #getOrCompute} never take a lock. Only the rotation swap itself is serialized (see
 * {@link #rotationLock}), so concurrent misses at capacity cannot cascade-rotate through several
 * generations and discard entries other threads just added.
 *
 * <p><b>Logging.</b> Every lookup logs a hit or a miss at {@code FINE}. Generation rotation logs
 * a {@link #statistics() statistics} snapshot: the first rotation at {@code INFO}, because that is
 * the point at which the cache reaches capacity and starts evicting, and every rotation after it at
 * {@code FINE}, so traffic with mostly unique certificates cannot flood the log. Rotation is used as
 * the reporting interval because it needs no timer and no clock reads on the request path.
 *
 * <p>Go through {@link #peek(String)} and {@link #getOrCompute(String, ParsedXfccSupplier)} on the
 * request path, so the implementation can be replaced without touching call sites and every lookup
 * is counted. {@link #get(String)} and {@link #put(String, ParsedXfcc)} remain for callers that need
 * the two halves separately.
 */
public final class CertificateCache {

    private static final Logger LOGGER = Logger.getLogger(CertificateCache.class.getName());

    private final int maxGenSize;

    private final LongAdder hits = new LongAdder();

    private final LongAdder misses = new LongAdder();

    private final LongAdder rotations = new LongAdder();

    /** Guards the one-off {@code INFO} log for the rotation that first takes the cache to capacity. */
    private final AtomicBoolean capacityReached = new AtomicBoolean();

    /**
     * Guards only the generation swap in {@link #rotateIfFull()}. Reads ({@link #get},
     * {@link #peek}) and cache hits never take this lock -- it is entered only on a miss that
     * finds the current generation already full, which is rare relative to overall traffic.
     * Without this guard, multiple threads can observe the same full generation concurrently and
     * each perform a swap, cascading through several generations in quick succession: this
     * discards entries other racing threads just added and breaks the {@code 2 * maxGenSize}
     * memory bound.
     */
    private final Object rotationLock = new Object();

    private volatile ConcurrentHashMap<String, ParsedXfcc> currentGen;
    private volatile ConcurrentHashMap<String, ParsedXfcc> prevGen;

    public CertificateCache(int maxGenSize) {
        this.maxGenSize = maxGenSize;
        this.currentGen = new ConcurrentHashMap<>();
        this.prevGen = new ConcurrentHashMap<>();
    }

    /** Returns the cached bundle for {@code key}, or {@code null} if not present. */
    public ParsedXfcc get(String key) {
        ParsedXfcc value = currentGen.get(key);
        if (value == null) {
            value = prevGen.get(key);
        }
        if (value == null) {
            recordMiss();
            return null;
        }
        recordHit();
        return value;
    }

    /**
     * Returns the cached bundle for {@code key}, or {@code null} if not present. Intended for
     * callers that need to short-circuit expensive work (such as parsing the raw header into an
     * {@link XfccEntry}) before they know whether the entry is even cache-eligible.
     *
     * <p>A found entry records a hit, since a caller finding a value here never proceeds to
     * {@link #getOrCompute} and so has no other opportunity to record it. A {@code null} result
     * stays silent and does <em>not</em> record a miss: the caller is expected to fall through to
     * {@link #getOrCompute}, which records the miss itself (and safely re-checks the key, so no
     * double-count can occur even if another thread inserts it in between).
     */
    ParsedXfcc peek(String key) {
        ParsedXfcc value = currentGen.get(key);
        if (value == null) {
            value = prevGen.get(key);
        }
        if (value != null) {
            recordHit();
        }
        return value;
    }

    /** Stores {@code value} under {@code key}, rotating generations if the current one is full. */
    public void put(String key, ParsedXfcc value) {
        rotateIfFull();
        currentGen.put(key, value);
    }

    /**
     * Returns the cached bundle for {@code key}, invoking {@code supplier} on a miss. The supplier
     * runs outside any lock; the result is published with {@code putIfAbsent}, so threads racing on
     * the same cold key may each parse it, but all of them receive the one instance that was stored.
     * Each call counts once: a hit when the value was already cached, a miss when this call parsed.
     *
     * <p>If {@code supplier} throws, the exception is propagated to the caller and no entry is
     * stored; the next request retries the parse.
     */
    public ParsedXfcc getOrCompute(String key, ParsedXfccSupplier supplier)
            throws CertificateException, IOException {
        ParsedXfcc value = currentGen.get(key);
        if (value != null) {
            recordHit();
            return value;
        }
        value = prevGen.get(key);
        if (value != null) {
            recordHit();
            return value;
        }
        recordMiss();
        ParsedXfcc parsed = supplier.parse();
        rotateIfFull();
        ParsedXfcc stored = currentGen.putIfAbsent(key, parsed);
        return stored != null ? stored : parsed;
    }

    private void rotateIfFull() {
        if (currentGen.size() >= maxGenSize) {
            synchronized (rotationLock) {
                // Re-check: another thread may have already rotated while this one waited for the lock.
                if (currentGen.size() >= maxGenSize) {
                    prevGen = currentGen;
                    currentGen = new ConcurrentHashMap<>();
                    this.rotations.increment();
                    logRotation();
                }
            }
        }
    }

    private void recordHit() {
        this.hits.increment();
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Certificate cache hit; skipping certificate parsing");
        }
    }

    private void recordMiss() {
        this.misses.increment();
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Certificate cache miss; the certificate will be parsed");
        }
    }

    /** Supplies a {@link ParsedXfcc} bundle on a cache miss. */
    @FunctionalInterface
    public interface ParsedXfccSupplier {

        ParsedXfcc parse() throws CertificateException, IOException;
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
            + ", hit rate=" + hitRate + "%, capacity=" + (2 * this.maxGenSize) + " parsed XFCC entries";
    }

    private void logRotation() {
        // The first rotation is the moment the cache fills up and starts evicting, so report it once at INFO
        // where operators will see it without turning on FINE. Later rotations are routine and stay at FINE:
        // traffic with mostly unique certificates rotates every maxGenSize misses and would flood the log.
        boolean first = this.capacityReached.compareAndSet(false, true);
        Level level = first ? Level.INFO : Level.FINE;
        if (!LOGGER.isLoggable(level)) {
            return;
        }
        String message = "Certificate cache rotated a generation (" + statistics()
            + "). A low hit rate means the working set of certificates exceeds the cache size; raise"
            + " org.cloudfoundry.router.certificate.cache.size to retain more of them.";
        LOGGER.log(level, message);
    }
}
