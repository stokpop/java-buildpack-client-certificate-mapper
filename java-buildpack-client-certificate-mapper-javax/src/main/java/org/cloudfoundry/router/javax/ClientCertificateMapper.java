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
import javax.servlet.http.HttpServletRequestWrapper;
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
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cloudfoundry.router.CertificateCache;
import org.cloudfoundry.router.CfSubjectDn;
import org.cloudfoundry.router.ParsedXfcc;
import org.cloudfoundry.router.XfccAttributes;
import org.cloudfoundry.router.XfccEntry;
import org.cloudfoundry.router.XfccField;
import org.cloudfoundry.router.XfccHeaderParser;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private static final String CACHE_ENABLED_PROPERTY = "org.cloudfoundry.router.certificate.cache.enabled";

    private static final String STRIP_HEADER_PROPERTY = "org.cloudfoundry.router.certificate.header.remove";

    private static final String CACHE_SIZE_PROPERTY = "org.cloudfoundry.router.certificate.cache.size";

    private static final int DEFAULT_CACHE_SIZE = 128;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final CertificateFactory certificateFactory;

    /** Cache keyed by a 64-character SHA-256 hex digest of the certificate bytes.
     *  Deriving the key ourselves — rather than trusting the XFCC {@code Hash=} field — avoids identity
     *  substitution: the header is not stripped by default, so external clients could inject any
     *  {@code Hash=} value. Deriving from the {@code Cert=} bytes (or the full raw header for non-XFCC
     *  requests) ensures only a request carrying the actual certificate can produce a hit.
     *  Using a short digest as the key keeps {@link String#hashCode()} and {@link String#equals(Object)}
     *  cheap on every lookup, so cache hits recover the parsing cost they were meant to save.
     *  {@code null} when caching is disabled.
     *  Memory note: keys are 64 bytes; with two generations of {@value #DEFAULT_CACHE_SIZE} entries each
     *  (default) the cache holds at most ~256 entries (~16 KB of key strings plus ~256 cert objects).
     *  See {@link CertificateCache}.
     *  Note: cached entries are not expiry-checked on retrieval — the filter does not validate cert validity
     *  on cache hits (nor on misses), consistent with the behaviour before caching was introduced. */
    private final CertificateCache certificateCache;

    /** When {@code true}, the {@code X-Forwarded-Client-Cert} header is hidden from downstream filters after parsing. */
    private final boolean stripXfccHeader;

    ClientCertificateMapper() throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        boolean cacheEnabled = !"false".equalsIgnoreCase(System.getProperty(CACHE_ENABLED_PROPERTY, "true"));
        int cacheSize = DEFAULT_CACHE_SIZE;
        if (cacheEnabled) {
            String cacheSizeProp = System.getProperty(CACHE_SIZE_PROPERTY);
            if (cacheSizeProp != null) {
                try {
                    cacheSize = Integer.parseInt(cacheSizeProp.trim());
                    if (cacheSize <= 0) {
                        this.logger.warning("Ignoring invalid " + CACHE_SIZE_PROPERTY + " value '" + cacheSizeProp + "'; using default " + DEFAULT_CACHE_SIZE);
                        cacheSize = DEFAULT_CACHE_SIZE;
                    }
                } catch (NumberFormatException e) {
                    this.logger.warning("Ignoring non-numeric " + CACHE_SIZE_PROPERTY + " value '" + cacheSizeProp + "'; using default " + DEFAULT_CACHE_SIZE);
                }
            }
            this.certificateCache = new CertificateCache(cacheSize);
        } else {
            this.certificateCache = null;
        }
        this.stripXfccHeader = "true".equalsIgnoreCase(System.getProperty(STRIP_HEADER_PROPERTY, "false"));
        logConfiguration(cacheEnabled, cacheSize);
    }

    /** Logs the effective filter configuration once at construction, so operators can confirm which
     *  behaviour is active without having to reason about system property defaults. */
    private void logConfiguration(boolean cacheEnabled, int cacheSize) {
        if (!this.logger.isLoggable(Level.INFO)) {
            return;
        }
        StringBuilder message = new StringBuilder("Mapping ").append(HEADER).append(" to the ").append(ATTRIBUTE).append(" request attribute; certificate cache ");
        if (cacheEnabled) {
            message.append("enabled (").append(CACHE_SIZE_PROPERTY).append('=').append(cacheSize).append(" entries per generation, up to ").append(2 * cacheSize).append(" cached certificates)");
        } else {
            message.append("disabled (").append(CACHE_ENABLED_PROPERTY).append("=false)");
        }
        message.append("; ").append(HEADER).append(" header stripping ");
        if (this.stripXfccHeader) {
            message.append("enabled (header hidden from downstream filters)");
        } else {
            message.append("disabled (").append(STRIP_HEADER_PROPERTY).append("=true to enable)");
        }
        this.logger.info(message.toString());
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
            // IllegalArgumentException: malformed %xx in URL-encoded cert value; treat same as parse failure
            } catch (CertificateException | IllegalArgumentException e) {
                this.logger.warning("Unable to parse certificates in X-Forwarded-Client-Cert");
            }
            // Only wrap when the header is actually present — avoids allocation on requests without a cert.
            if (this.stripXfccHeader && ((HttpServletRequest) request).getHeader(HEADER) != null) {
                request = new XfccStrippingRequestWrapper((HttpServletRequest) request);
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
                return URLDecoder.decode(rawCertificate, "utf-8").getBytes(StandardCharsets.UTF_8);
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

    /** Parses the raw XFCC header value into a {@link ParsedXfcc} bundle: the {@link XfccEntry},
     *  the decoded {@link X509Certificate} (if a {@code Cert=} field is present or the value is a
     *  raw certificate), and the {@link CfSubjectDn} derived from any {@code Subject=} field.
     *  On the cache miss path this is invoked exactly once per key by
     *  {@link CertificateCache#getOrCompute}. */
    private ParsedXfcc parseRawValue(String rawValue) throws CertificateException, IOException {
        XfccEntry xfcc = new XfccEntry(rawValue);
        if (xfcc.resemblesXfcc()) {
            if (this.logger.isLoggable(Level.FINE)) {
                this.logger.fine("XFCC entry received with fields: " + xfcc.fieldNames());
            }
            if (xfcc.hasField(XfccField.HASH) && !XfccHeaderParser.isValidSha256Hex(xfcc.get(XfccField.HASH))) {
                this.logger.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest");
            }
            X509Certificate cert = null;
            if (xfcc.hasField(XfccField.CERT)) {
                cert = generateCertificate(xfcc.get(XfccField.CERT));
            } else if (xfcc.hasField(XfccField.CHAIN)) {
                this.logger.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
            }
            CfSubjectDn dn = xfcc.hasField(XfccField.SUBJECT)
                    ? XfccHeaderParser.parseCfSubjectDn(xfcc.get(XfccField.SUBJECT))
                    : null;
            return new ParsedXfcc(xfcc, cert, dn);
        }
        // Non-XFCC raw cert: no XFCC fields to extract, no CF DN.
        return new ParsedXfcc(xfcc, generateCertificate(rawValue), null);
    }

    /** Returns the parsed bundle for {@code rawValue}, using the cache when enabled. When the
     *  SHA-256 algorithm is unavailable (extremely unusual — logged once by {@link #sha256Hex})
     *  the request falls back to inline parsing rather than caching under an unsafe long key. */
    private ParsedXfcc resolve(String rawValue) throws CertificateException, IOException {
        if (this.certificateCache != null) {
            String cacheKey = sha256Hex(rawValue);
            if (cacheKey != null) {
                return this.certificateCache.getOrCompute(cacheKey, () -> parseRawValue(rawValue));
            }
        }
        return parseRawValue(rawValue);
    }

    /** Returns the SHA-256 digest of {@code input} as 64 lowercase hex characters, or {@code null} if
     *  the SHA-256 algorithm is unavailable (in which case the caller falls back to no caching for that
     *  request rather than using an unsafe long key). MessageDigest instances are not thread-safe, so a
     *  fresh one is obtained per call; the cost is dominated by the digest computation itself.
     *  Note: {@code input} is the URL-encoded PEM or base64 DER header value — not the decoded DER —
     *  so this digest intentionally differs from the Envoy XFCC {@code Hash=} field. This is fine for
     *  cache identity but the two values must not be compared. */
    private String sha256Hex(String input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            this.logger.warning("SHA-256 algorithm not available; skipping certificate cache for this request");
            return null;
        }
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        char[] out = new char[digest.length * 2];
        for (int i = 0; i < digest.length; i++) {
            int b = digest[i] & 0xff;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0x0f];
        }
        return new String(out);
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawValue : getRawCertificates(request)) {
            ParsedXfcc parsed = resolve(rawValue);
            setXfccAttributes(request, parsed);
            if (parsed.certificate() != null) {
                certificates.add(parsed.certificate());
            }
        }

        return certificates;
    }

    private void setXfccAttributes(HttpServletRequest request, ParsedXfcc parsed) {
        XfccEntry xfcc = parsed.xfcc();
        if (!xfcc.resemblesXfcc()) {
            return;
        }
        if (request.getAttribute(XfccAttributes.HASH) == null && xfcc.hasField(XfccField.HASH)) {
            request.setAttribute(XfccAttributes.HASH, xfcc.get(XfccField.HASH));
        }
        if (request.getAttribute(XfccAttributes.SUBJECT) == null && xfcc.hasField(XfccField.SUBJECT)) {
            request.setAttribute(XfccAttributes.SUBJECT, xfcc.get(XfccField.SUBJECT));
            setCfSubjectAttributes(request, parsed.cfSubjectDn());
        }
    }

    private void setCfSubjectAttributes(HttpServletRequest request, CfSubjectDn dn) {
        if (dn == null) {
            return;
        }
        if (request.getAttribute(XfccAttributes.APP_GUID) == null && dn.appGuid != null) {
            request.setAttribute(XfccAttributes.APP_GUID, dn.appGuid);
        }
        if (request.getAttribute(XfccAttributes.SPACE_GUID) == null && dn.spaceGuid != null) {
            request.setAttribute(XfccAttributes.SPACE_GUID, dn.spaceGuid);
        }
        if (request.getAttribute(XfccAttributes.ORG_GUID) == null && dn.orgGuid != null) {
            request.setAttribute(XfccAttributes.ORG_GUID, dn.orgGuid);
        }
        if (request.getAttribute(XfccAttributes.INSTANCE_GUID) == null && dn.instanceGuid != null) {
            request.setAttribute(XfccAttributes.INSTANCE_GUID, dn.instanceGuid);
        }
    }

    private List<String> getRawCertificates(HttpServletRequest request) {
        return XfccHeaderParser.splitHeaderValues(Collections.list(request.getHeaders(HEADER)));
    }

    private static final class XfccStrippingRequestWrapper extends HttpServletRequestWrapper {

        XfccStrippingRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return null;
            }
            return super.getHeader(name);
        }

        @Override
        public long getDateHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return -1;
            }
            return super.getDateHeader(name);
        }

        @Override
        public int getIntHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return -1;
            }
            return super.getIntHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return Collections.enumeration(Collections.<String>emptyList());
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Enumeration<String> orig = super.getHeaderNames();
            if (orig == null) {
                return null;
            }
            List<String> names = Collections.list(orig);
            names.removeIf(name -> HEADER.equalsIgnoreCase(name));
            return Collections.enumeration(names);
        }
    }

}
