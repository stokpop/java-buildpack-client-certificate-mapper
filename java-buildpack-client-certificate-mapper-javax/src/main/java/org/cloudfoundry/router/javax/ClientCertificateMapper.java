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

package org.cloudfoundry.router.javax;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private static final List<String> XFCC_KEYS = Arrays.asList("By=", "Hash=", "Cert=", "Chain=", "Subject=", "URI=", "DNS=");

    private static final String CACHE_ENABLED_PROPERTY = "org.cloudfoundry.router.certificate.cache.enabled";

    private static final String RAW_CACHE_KEY_PROPERTY = "org.cloudfoundry.router.certificate.cache.raw.key";

    private static final int MAX_CACHE_SIZE = 100;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final CertificateFactory certificateFactory;

    /** Keyed by the XFCC {@code Hash=} fingerprint or a derived raw-cert key. {@code null} when caching is disabled. */
    private final Map<String, X509Certificate> certificateCache;

    /** When {@code true}, the full raw header value is used as the cache key for non-XFCC certs; otherwise SHA-256 is used. */
    private final boolean rawCacheKeyFull;

    ClientCertificateMapper() throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        boolean cacheEnabled = !"false".equalsIgnoreCase(System.getProperty(CACHE_ENABLED_PROPERTY, "true"));
        this.certificateCache = cacheEnabled ? new ConcurrentHashMap<>() : null;
        this.rawCacheKeyFull = "full".equalsIgnoreCase(System.getProperty(RAW_CACHE_KEY_PROPERTY, "sha256"));
    }

    @Override
    public void destroy() {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            try {
                List<X509Certificate> certificates = getCertificates((HttpServletRequest) request);

                if (!certificates.isEmpty()) {
                    request.setAttribute(ATTRIBUTE, certificates.toArray(new X509Certificate[0]));
                }
            } catch (CertificateException e) {
                this.logger.warning("Unable to parse certificates in X-Forwarded-Client-Cert");
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    private byte[] decodeHeader(String rawCertificate) {
        try {
            return Base64.getDecoder().decode(rawCertificate);
        } catch (IllegalArgumentException e1) {
            try {
                return URLDecoder.decode(rawCertificate, "utf-8").getBytes();
            } catch (UnsupportedEncodingException e2) {
                throw new IllegalArgumentException("Header contains value that is neither base64 nor url encoded");
            }
        }
    }

    private X509Certificate generateCertificate(String certData) throws CertificateException, IOException {
        try (InputStream in = new ByteArrayInputStream(decodeHeader(certData))) {
            return (X509Certificate) this.certificateFactory.generateCertificate(in);
        }
    }

    private String xfccFieldNames(String xfccEntry) {
        StringBuilder names = new StringBuilder();
        for (String key : XFCC_KEYS) {
            if (extractFieldFromXfcc(xfccEntry, key) != null) {
                if (names.length() > 0) names.append(", ");
                names.append(key, 0, key.length() - 1); // strip trailing '='
            }
        }
        return names.toString();
    }

    private X509Certificate parseCertificate(String rawValue) throws CertificateException, IOException {
        if (isXfccFormat(rawValue)) {
            this.logger.fine("XFCC entry received with fields: " + xfccFieldNames(rawValue));
            String hash = extractFieldFromXfcc(rawValue, "Hash=");
            if (hash != null && this.certificateCache != null) {
                X509Certificate cached = this.certificateCache.get(hash);
                if (cached != null) {
                    return cached;
                }
            }
            String certData = extractFieldFromXfcc(rawValue, "Cert=");
            if (certData == null) {
                certData = extractFieldFromXfcc(rawValue, "Chain=");
            }
            if (certData == null) {
                return null;
            }
            X509Certificate cert = generateCertificate(certData);
            if (hash != null && this.certificateCache != null && this.certificateCache.size() < MAX_CACHE_SIZE) {
                this.certificateCache.put(hash, cert);
            }
            return cert;
        }
        // Computing the cache key (SHA-256 or identity) is cheaper than parsing the raw value into an X509Certificate each time.
        if (this.certificateCache != null) {
            String cacheKey = computeRawCacheKey(rawValue);
            X509Certificate cached = this.certificateCache.get(cacheKey);
            if (cached != null) {
                return cached;
            }
            X509Certificate cert = generateCertificate(rawValue);
            if (this.certificateCache.size() < MAX_CACHE_SIZE) {
                this.certificateCache.put(cacheKey, cert);
            }
            return cert;
        }
        return generateCertificate(rawValue);
    }

    private String computeRawCacheKey(String rawValue) {
        if (this.rawCacheKeyFull) {
            return rawValue;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawValue.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawCertificate : getRawCertificates(request)) {
            try (InputStream in = new ByteArrayInputStream(decodeHeader(rawCertificate))) {
                certificates.add((X509Certificate) this.certificateFactory.generateCertificate(in));
            }
        }

        return certificates;
    }

    private List<String> getRawCertificates(HttpServletRequest request) {
        Enumeration<String> candidates = request.getHeaders(HEADER);

        if (candidates == null) {
            return Collections.emptyList();
        }

        List<String> rawCertificates = new ArrayList<>();
        while (candidates.hasMoreElements()) {
            String candidate = candidates.nextElement();

            if (hasMultipleCertificates(candidate)) {
                rawCertificates.addAll(Arrays.asList(candidate.split(",")));
            } else {
                rawCertificates.add(candidate);
            }
        }

        return rawCertificates;
    }

    private boolean hasMultipleCertificates(String candidate) {
        return candidate.indexOf(',') != -1;
    }

}
