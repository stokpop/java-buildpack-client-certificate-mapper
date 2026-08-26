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

/**
 * A bounded, lock-free certificate cache based on a generational eviction strategy.
 *
 * <p>Two generations of {@link ConcurrentHashMap} are maintained: {@code currentGen} and
 * {@code prevGen}. Lookups check current first, then previous. When the current generation
 * reaches {@code maxGenSize}, it is promoted to previous (the old previous is discarded) and
 * a fresh current generation starts. This keeps memory bounded at approximately
 * {@code 2 * maxGenSize} entries while avoiding any locking on the read path.
 *
 * <p><b>Memory budget.</b> Keys for XFCC entries are 64-byte SHA-256 hex strings (from the
 * router-supplied {@code Hash=} field). Keys for raw (non-XFCC) entries are the full header
 * value — typically 2–4 KB of base64/URL-encoded DER. With the default generation size of 128,
 * the cache holds at most ~256 {@code X509Certificate} objects plus ~1 MB of raw-cert key
 * strings, for a worst-case total of roughly 1.5 MB. If this is a concern, disable caching
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
 * <p>Use {@link #get(String)} and {@link #put(String, X509Certificate)} as the only entry
 * points so the implementation can be replaced without touching call sites.
 */
public final class CertificateCache {

    private final int maxGenSize;

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
        if (cert != null) {
            return cert;
        }
        return prevGen.get(key);
    }

    /** Stores {@code cert} under {@code key}, rotating generations if the current one is full. */
    public void put(String key, X509Certificate cert) {
        if (currentGen.size() >= maxGenSize) {
            prevGen = currentGen;
            currentGen = new ConcurrentHashMap<>();
        }
        currentGen.put(key, cert);
    }
}
