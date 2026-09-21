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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Compares the two cache key strategies on the path a request actually takes: a SHA-256 hex digest
 * of the header value against using the header value itself as the map key.
 *
 * <p>Both variants start from a freshly built {@link String}, because that is what a request
 * produces -- the header value is substring-parsed per request, so it is a new object whose
 * {@code hashCode} has never been computed. Measuring a lookup with a key computed beforehand
 * flatters the digest strategy by charging it nothing for the digest it must take on every request.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class CacheKeyBenchmark {

    /** Header size in bytes; roughly a base64 DER leaf certificate and an Envoy PEM one. */
    @Param({"1300", "2400"})
    public int headerSize;

    private char[] header;

    private ConcurrentHashMap<String, Object> byDigest;

    private ConcurrentHashMap<String, Object> byRawValue;

    @Setup
    public void setUp() throws Exception {
        StringBuilder builder = new StringBuilder(this.headerSize);
        for (int i = 0; i < this.headerSize; i++) {
            builder.append((char) ('A' + (i % 26)));
        }
        this.header = builder.toString().toCharArray();

        String value = new String(this.header);
        Object parsed = new Object();
        this.byDigest = new ConcurrentHashMap<>();
        this.byDigest.put(sha256Hex(value), parsed);
        this.byRawValue = new ConcurrentHashMap<>();
        this.byRawValue.put(value, parsed);
    }

    @Benchmark
    public Object digestKey() throws Exception {
        return this.byDigest.get(sha256Hex(new String(this.header)));
    }

    @Benchmark
    public Object rawValueKey() {
        return this.byRawValue.get(new String(this.header));
    }

    private static String sha256Hex(String input) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

}
