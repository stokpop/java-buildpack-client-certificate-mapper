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

package org.cloudfoundry.router.benchmark;

import org.cloudfoundry.router.CertificateCache;
import org.cloudfoundry.router.ParsedXfcc;
import org.cloudfoundry.router.XfccResolver;
import org.openjdk.jol.info.GraphLayout;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Reports the retained heap of a full certificate cache, per header form. Run on JDK 21 or older
 * (JOL cannot walk some JDK-internal records on 25):
 *
 * <pre>
 * java -cp java-buildpack-client-certificate-mapper-benchmark/target/benchmarks.jar \
 *      org.cloudfoundry.router.benchmark.CacheFootprint
 * </pre>
 *
 * <p>Fills both generations of a default-sized cache (128 per generation, so 256 distinct entries)
 * and walks the object graph exactly. Reports the key strings on their own and the full cache, so
 * the cost of keying on the header value can be separated from the cost of the parsed bundle it
 * points at. A whole-heap {@code System.gc()} delta cannot resolve this: the quantities are
 * hundreds of KB against a heap measured in hundreds of MB.
 */
public final class CacheFootprint {

    private static final int GENERATION_SIZE = 128;

    private static final int ENTRIES = 2 * GENERATION_SIZE;

    private CacheFootprint() {
    }

    public static void main(String[] args) throws Exception {
        System.out.printf("%-14s %10s %12s %12s %12s %12s%n",
                "form", "header B", "key B/e", "entry B/e", "total KB", "cert x DER");
        for (XfccCorpus.Form form : XfccCorpus.Form.values()) {
            String[] headers = XfccCorpus.build(form, ENTRIES);

            ConcurrentHashMap<String, Object> keys = new ConcurrentHashMap<>();
            for (String header : headers) {
                keys.put(header, Boolean.TRUE);
            }
            long keysSize = GraphLayout.parseInstance(keys).totalSize();

            CertificateCache cache = new CertificateCache(GENERATION_SIZE);
            XfccResolver resolver = new XfccResolver(cache);
            for (String header : headers) {
                resolver.resolve(header);
            }
            long fullSize = GraphLayout.parseInstance(cache).totalSize();

            ParsedXfcc sample = resolver.resolve(headers[0]);
            String expansion = "n/a";
            if (sample.certificate() != null) {
                long der = sample.certificate().getEncoded().length;
                long graph = GraphLayout.parseInstance(sample.certificate()).totalSize();
                expansion = String.format("%.1fx", graph / (double) der);
            }

            System.out.printf("%-14s %10d %12d %12d %12d %12s%n",
                    form, headers[0].length(), keysSize / ENTRIES, fullSize / ENTRIES,
                    fullSize / 1024, expansion);
        }
    }

}
