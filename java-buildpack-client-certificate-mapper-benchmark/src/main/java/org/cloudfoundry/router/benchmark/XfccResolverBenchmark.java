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

package org.cloudfoundry.router.benchmark;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.router.CertificateCache;
import org.cloudfoundry.router.ParsedXfcc;
import org.cloudfoundry.router.XfccResolver;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.security.Security;
import java.util.concurrent.TimeUnit;

/**
 * Compares resolving an {@code X-Forwarded-Client-Cert} entry with the certificate cache enabled
 * against resolving it with the cache disabled.
 *
 * <p>This measures the filter-internal cost only -- one {@link XfccResolver#resolve(String)} call.
 * It says nothing about end-to-end request latency, where this cost is a small fraction of the
 * work an application does per request.
 *
 * <p>Run all of it, with per-operation allocation, at four thread counts:
 *
 * <pre>
 * ./mvnw -Pbenchmarks -DskipTests package
 * java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 1
 * java -jar java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar -prof gc -t 4
 * </pre>
 *
 * <p>The three header forms are not equally interesting. {@code RAW_BASE64} is a whole leaf
 * certificate, as CF Gorouter forwards it with {@code xfcc_format: raw} for client certificates
 * arriving from outside the platform: a cache hit skips the ASN.1 parse and reuses the
 * {@code X509Certificate} object, which is where the cache earns its keep. {@code CERT_FIELD} is
 * the Envoy equivalent, with the certificate as URL-encoded PEM. {@code IDENTITY_ONLY} is the CF
 * app-identity header on an mTLS domain ({@code Hash=} and {@code Subject=} only): there is no
 * certificate to parse, so a hit saves only the field scan and the Subject DN parse, and on a miss
 * the cache lookup, insert and generation bookkeeping are added cost.
 *
 * <p>{@code workingSet} is the number of distinct certificates in rotation. The cache holds two
 * generations of {@code cache.size} entries (128 by default, so ~256 certificates), which means a
 * working set of 512 deliberately exceeds it: that run shows what the cache costs when it mostly
 * misses.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
@State(Scope.Benchmark)
public class XfccResolverBenchmark {

    @Param({"CERT_FIELD", "RAW_BASE64", "IDENTITY_ONLY"})
    public XfccCorpus.Form form;

    @Param({"1", "16", "512"})
    public int workingSet;

    /**
     * Entries per cache generation, so the cache holds twice this. Raise it past 375 to exceed the
     * JDK's own parsed-certificate cache ({@code sun.security.provider.X509Factory.certCache}, 750
     * soft-referenced entries keyed by the DER bytes), which otherwise serves the no-cache variant
     * too and hides what parsing a cold certificate really costs.
     */
    @Param({"128"})
    public int cacheSize;

    /**
     * The JCA provider that parses certificates: empty for the platform default ({@code SUN} on a
     * stock JVM), or a registered provider's name. This changes what a cache *miss* costs, and so
     * what the cache is worth: {@code SUN} keeps its own 750-entry certificate cache, which serves
     * the no-cache variant too whenever the working set fits in it, while BouncyCastle has no such
     * cache and pays a full parse on every miss.
     */
    @Param({"", "BC"})
    public String provider;

    /**
     * Header values as character arrays, not strings. Each operation builds a fresh {@link String}
     * from one of them, because that is what a request produces: the header value is substring-
     * parsed per request, so its {@code hashCode} has never been computed and it is never the same
     * object the cache stored. Reusing one {@code String} instance across operations would let
     * {@code String.hashCode()} be cached and {@code equals()} short-circuit on reference identity,
     * which flatters any strategy that keys on the value itself by around two orders of magnitude.
     */
    private char[][] headers;

    private XfccResolver cached;

    private XfccResolver uncached;

    @Setup
    public void setUp() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        String[] corpus = XfccCorpus.build(this.form, this.workingSet);
        this.headers = new char[corpus.length][];
        for (int i = 0; i < corpus.length; i++) {
            this.headers[i] = corpus[i].toCharArray();
        }
        this.cached = new XfccResolver(new CertificateCache(this.cacheSize), this.provider);
        this.uncached = new XfccResolver(null, this.provider);

        // Prime the cache so steady-state measurement is not dominated by first-touch misses.
        for (char[] header : this.headers) {
            this.cached.resolve(new String(header));
        }
    }

    @Benchmark
    public ParsedXfcc cacheEnabled(Cursor cursor) throws Exception {
        return this.cached.resolve(nextHeader(cursor));
    }

    @Benchmark
    public ParsedXfcc cacheDisabled(Cursor cursor) throws Exception {
        return this.uncached.resolve(nextHeader(cursor));
    }

    /** A fresh {@code String} for this operation, as request parsing would produce. */
    private String nextHeader(Cursor cursor) {
        return new String(this.headers[cursor.next(this.headers.length)]);
    }

    /**
     * Per-thread cursor over the corpus. Each thread walks the headers from its own offset, so
     * threads work on different entries rather than all hammering the same cache key.
     */
    @State(Scope.Thread)
    public static class Cursor {

        private int index = System.identityHashCode(Thread.currentThread());

        public int next(int length) {
            int next = this.index++ % length;
            return next < 0 ? -next : next;
        }

    }

}
