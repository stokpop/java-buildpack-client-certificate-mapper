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

package org.cloudfoundry.router.jakarta;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import static java.nio.charset.StandardCharsets.UTF_8;
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import org.cloudfoundry.router.CfSubjectDn;
import org.cloudfoundry.router.XfccAttributes;
import org.cloudfoundry.router.XfccEntry;
import org.cloudfoundry.router.XfccField;
import org.cloudfoundry.router.XfccHeaderParser;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code jakarta.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private static final String CACHE_ENABLED_PROPERTY = "org.cloudfoundry.router.certificate.cache.enabled";

    private static final String RAW_CACHE_KEY_PROPERTY = "org.cloudfoundry.router.certificate.cache.raw.key";

    private static final String STRIP_HEADER_PROPERTY = "org.cloudfoundry.router.certificate.header.remove";

    private static final int MAX_CACHE_SIZE = 100;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final CertificateFactory certificateFactory;

    /** Keyed by the XFCC {@code Hash=} fingerprint or a derived raw-cert key. {@code null} when caching is disabled. */
    private final Map<String, X509Certificate> certificateCache;

    /** When {@code true}, the full raw header value is used as the cache key for non-XFCC certs; otherwise SHA-256 is used. */
    private final boolean rawCacheKeyFull;

    /** When {@code true}, the {@code X-Forwarded-Client-Cert} header is hidden from downstream filters after parsing. */
    private final boolean stripXfccHeader;

    ClientCertificateMapper() throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        boolean cacheEnabled = !"false".equalsIgnoreCase(System.getProperty(CACHE_ENABLED_PROPERTY, "true"));
        this.certificateCache = cacheEnabled ? new ConcurrentHashMap<>() : null;
        this.rawCacheKeyFull = "full".equalsIgnoreCase(System.getProperty(RAW_CACHE_KEY_PROPERTY, "sha256"));
        this.stripXfccHeader = "true".equalsIgnoreCase(System.getProperty(STRIP_HEADER_PROPERTY, "false"));
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

    private X509Certificate parseCertificate(String rawValue, XfccEntry xfcc) throws CertificateException, IOException {
        if (xfcc.resemblesXfcc()) {
            if (this.logger.isLoggable(java.util.logging.Level.FINE)) {
                this.logger.fine("XFCC entry received with fields: " + xfcc.fieldNames());
            }
            String hash = xfcc.get(XfccField.HASH);
            if (xfcc.hasField(XfccField.HASH) && !XfccHeaderParser.isValidSha256Hex(hash)) {
                this.logger.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest");
            }
            if (hash != null && this.certificateCache != null) {
                X509Certificate cached = this.certificateCache.get(hash);
                if (cached != null) {
                    return cached;
                }
            }
            if (!xfcc.hasField(XfccField.CERT)) {
                if (xfcc.hasField(XfccField.CHAIN)) {
                    this.logger.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
                }
                return null;
            }
            X509Certificate cert = generateCertificate(xfcc.get(XfccField.CERT));
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
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawValue.getBytes(UTF_8));
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

        for (String rawValue : getRawCertificates(request)) {
            XfccEntry xfcc = new XfccEntry(rawValue);
            setXfccAttributes(request, xfcc);
            X509Certificate cert = parseCertificate(rawValue, xfcc);
            if (cert != null) {
                certificates.add(cert);
            }
        }

        return certificates;
    }

    private void setXfccAttributes(HttpServletRequest request, XfccEntry xfcc) {
        if (!xfcc.resemblesXfcc()) {
            return;
        }
        if (request.getAttribute(XfccAttributes.HASH) == null && xfcc.hasField(XfccField.HASH)) {
            request.setAttribute(XfccAttributes.HASH, xfcc.get(XfccField.HASH));
        }
        if (request.getAttribute(XfccAttributes.SUBJECT) == null && xfcc.hasField(XfccField.SUBJECT)) {
            String subject = xfcc.get(XfccField.SUBJECT);
            request.setAttribute(XfccAttributes.SUBJECT, subject);
            setCfSubjectAttributes(request, subject);
        }
    }

    private void setCfSubjectAttributes(HttpServletRequest request, String subject) {
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn(subject);
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
        public Enumeration<String> getHeaders(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return Collections.emptyEnumeration();
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            names.removeIf(name -> HEADER.equalsIgnoreCase(name));
            return Collections.enumeration(names);
        }
    }

}
