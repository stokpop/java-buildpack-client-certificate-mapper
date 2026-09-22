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

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/**
 * Plain threads, no JMH: {@code threads} threads parse a rotating set of 16 certificates for
 * {@code millis}, reporting aggregate throughput.
 *
 * <p>Deliberately avoids JMH, whose generated state-init monitor dominates a
 * {@code jdk.JavaMonitorEnter} recording and is easy to mistake for the lock being investigated.
 * Run under JFR with the monitor threshold at zero, since the individual stalls are microseconds:
 *
 * <pre>
 * java -XX:StartFlightRecording=filename=probe.jfr,settings=profile,\
 *          jdk.JavaMonitorEnter#threshold=0ms,jdk.JavaMonitorEnter#enabled=true \
 *      -cp java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar \
 *      org.cloudfoundry.router.benchmark.ParseLockProbe SUN 4 8000
 * jfr print --events jdk.JavaMonitorEnter probe.jfr
 * </pre>
 *
 * <p>Pass {@code SUN}, {@code BC} (BouncyCastle) or any provider class name as the provider, and
 * optionally the number of distinct certificates to rotate through
 * (16 by default; more than 750 defeats the JVM's own certificate cache). Providers other than
 * {@code SUN} are instantiated reflectively and must be on the classpath, so this module depends on
 * none of them. With {@code SUN}, the stacks name {@code X509Factory.getFromCache} blocking on the
 * class monitor.
 */
public final class ParseLockProbe {

    private ParseLockProbe() {
    }

    public static void main(String[] args) throws Exception {
        String provider = args[0];
        int threads = Integer.parseInt(args[1]);
        long millis = Long.parseLong(args[2]);
        int distinct = args.length > 3 ? Integer.parseInt(args[3]) : 16;

        byte[][] der = new byte[distinct][];
        String[] headers = XfccCorpus.build(XfccCorpus.Form.RAW_BASE64, der.length);
        for (int i = 0; i < der.length; i++) {
            der[i] = Base64.getDecoder().decode(headers[i]);
        }

        // One factory shared by all threads, unlike XfccResolver's factory per parse. Safe here: the
        // input is plain DER only, where a shared BouncyCastle factory's per-parse state never
        // crosses threads (its PKCS#7 path is what races), and any failed parse fails the probe.
        CertificateFactory factory = "SUN".equals(provider)
                ? CertificateFactory.getInstance("X.509", "SUN")
                : CertificateFactory.getInstance("X.509", register(provider));

        LongAdder ops = new LongAdder();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch start = new CountDownLatch(1);
        long deadline = System.currentTimeMillis() + millis;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            workers[t] = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    return;
                }
                int i = 0;
                try {
                    while (System.currentTimeMillis() < deadline) {
                        for (int n = 0; n < 100; n++) {
                            factory.generateCertificate(new ByteArrayInputStream(der[i++ % der.length]));
                        }
                        ops.add(100);
                    }
                } catch (Exception e) {
                    failure.compareAndSet(null, e);
                }
            }, "parser-" + t);
            workers[t].start();
        }
        long t0 = System.nanoTime();
        start.countDown();
        for (Thread w : workers) {
            w.join();
        }
        // A failed parse must fail the probe, not show up as merely lower throughput.
        if (failure.get() != null) {
            throw new IllegalStateException("A parser thread failed", failure.get());
        }
        double seconds = (System.nanoTime() - t0) / 1e9;
        System.out.printf("%-10s threads=%d distinct=%-5d %,10.0f parses/s (%6.2f us/op per thread)%n",
                provider, threads, distinct, ops.sum() / seconds,
                seconds * 1e6 / (ops.sum() / (double) threads));
    }

    /** Registers a provider by short name, instantiating it reflectively so it stays optional. */
    private static String register(String provider) throws Exception {
        if (Security.getProvider(provider) != null) {
            return provider;
        }
        String className;
        if ("BC".equals(provider)) {
            className = "org.bouncycastle.jce.provider.BouncyCastleProvider";
        } else if ("BCFIPS".equals(provider)) {
            className = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
        } else {
            className = provider;
        }
        java.security.Provider instance =
                (java.security.Provider) Class.forName(className).getDeclaredConstructor().newInstance();
        Security.addProvider(instance);
        return instance.getName();
    }
}
