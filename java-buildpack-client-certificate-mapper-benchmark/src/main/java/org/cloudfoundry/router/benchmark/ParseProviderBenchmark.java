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

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Compares certificate parsing through the JDK's {@code SUN} provider against BouncyCastle.
 *
 * <p>The JDK's {@code X509Factory} caches parsed certificates in a 750-entry soft cache keyed by
 * the DER bytes, and reaches it through {@code static synchronized} helpers, so every parse in the
 * JVM serializes on one monitor. BouncyCastle has no such cache and no such lock. Two working-set
 * sizes separate the effects: {@code distinct=16} fits the JDK cache (so SUN measures a cache hit
 * plus the lock), {@code distinct=2000} does not (so SUN measures a real parse plus the lock).
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class ParseProviderBenchmark {

    @Param({"SUN", "BC"})
    public String provider;

    @Param({"16", "2000"})
    public int distinct;

    private byte[][] der;

    private CertificateFactory factory;

    @Setup
    public void setUp() throws Exception {
        String[] headers = XfccCorpus.build(XfccCorpus.Form.RAW_BASE64, this.distinct);
        this.der = new byte[headers.length][];
        for (int i = 0; i < headers.length; i++) {
            this.der[i] = Base64.getDecoder().decode(headers[i]);
        }

        if ("BC".equals(this.provider)) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            this.factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        } else {
            this.factory = CertificateFactory.getInstance("X.509");
        }
    }

    @Benchmark
    public Certificate parse(XfccResolverBenchmark.Cursor cursor) throws Exception {
        byte[] encoded = this.der[cursor.next(this.der.length)];
        return this.factory.generateCertificate(new ByteArrayInputStream(encoded));
    }

}
