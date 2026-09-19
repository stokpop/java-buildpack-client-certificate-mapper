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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Servlet-independent core of the client-certificate mapper: turns a single raw
 * {@code X-Forwarded-Client-Cert} header entry into a {@link ParsedXfcc} bundle, decoding any
 * certificate and parsing the XFCC fields, optionally using a {@link CertificateCache}.
 *
 * <p>This logic is shared by the {@code javax} and {@code jakarta} filters so the two differ only in
 * their Servlet-API-specific glue (reading headers, setting request attributes, header stripping).
 */
public final class XfccResolver {

    private static final Logger LOGGER = Logger.getLogger(XfccResolver.class.getName());

    private final CertificateFactory certificateFactory;

    /** {@code null} when caching is disabled. */
    private final CertificateCache certificateCache;

    /** @param certificateCache the cache to use, or {@code null} to disable caching */
    public XfccResolver(CertificateCache certificateCache) throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificateCache = certificateCache;
    }

    /** The certificate cache in use, or {@code null} when caching is disabled. */
    public CertificateCache cache() {
        return this.certificateCache;
    }

    /** Returns the parsed bundle for {@code rawValue}, using the cache when enabled. The cache is
     *  keyed by the header value itself and consulted, via {@link CertificateCache#peek},
     *  <em>before</em> {@code rawValue} is parsed into an {@link XfccEntry} -- a hit returns the
     *  previously cached bundle directly, so a repeat of the same header does not re-run the one-pass
     *  field scan just to discard it. Only a byte-for-byte identical header value can hit, and
     *  {@link String#equals(Object)} confirms every hit, so no key derivation can map two different
     *  headers onto one certificate.
     *
     *  <p>Keying on the value rather than on a digest of it was measured to be the cheaper of the
     *  two on the request path: each request produces a fresh {@code String} from header parsing, so
     *  {@link String#hashCode()} traverses the value once per lookup at roughly one cycle per byte,
     *  where a SHA-256 digest of the same value costs roughly ten cycles per byte on hardware without
     *  SHA extensions -- more than the certificate parse it is there to avoid. See
     *  {@code docs/PERFORMANCE.md}.
     *
     *  <p>Every entry is cached on a miss, including identity-only XFCC headers (e.g. CF app-identity
     *  headers carrying only {@code Hash=}/{@code Subject=}) and unsupported {@code Chain=}-only
     *  entries: those have no expensive ASN.1 parse to amortise, but a repeat still skips the field-map
     *  and Subject DN parse. */
    public ParsedXfcc resolve(String rawValue) throws CertificateException, IOException {
        if (this.certificateCache != null) {
            ParsedXfcc cached = this.certificateCache.peek(rawValue);
            if (cached != null) {
                return cached;
            }
            return this.certificateCache.getOrCompute(rawValue, () -> parseEntry(new XfccEntry(rawValue), rawValue));
        }
        return parseEntry(new XfccEntry(rawValue), rawValue);
    }

    /** Parses a pre-detected {@link XfccEntry} into a {@link ParsedXfcc} bundle: the entry, the
     *  decoded {@link X509Certificate} (if a {@code Cert=} field is present or the value is a raw
     *  certificate), and the {@link CfSubjectDn} derived from any {@code Subject=} field.
     *  On the cache miss path this is invoked exactly once per key by
     *  {@link CertificateCache#getOrCompute}. */
    private ParsedXfcc parseEntry(XfccEntry xfcc, String rawValue) throws CertificateException, IOException {
        if (xfcc.resemblesXfcc()) {
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("XFCC entry received with fields: " + xfcc.fieldNames());
            }
            if (xfcc.hasField(XfccField.HASH) && !XfccHeaderParser.isValidSha256Hex(xfcc.get(XfccField.HASH))) {
                LOGGER.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest");
            }
            X509Certificate cert = null;
            if (xfcc.hasField(XfccField.CERT)) {
                cert = generateCertificate(xfcc.get(XfccField.CERT));
            } else if (xfcc.hasField(XfccField.CHAIN)) {
                LOGGER.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
            }
            CfSubjectDn dn = xfcc.hasField(XfccField.SUBJECT)
                    ? XfccHeaderParser.parseCfSubjectDn(xfcc.get(XfccField.SUBJECT))
                    : null;
            return new ParsedXfcc(xfcc, cert, dn);
        }
        // Non-XFCC raw cert: no XFCC fields to extract, no CF DN.
        return new ParsedXfcc(xfcc, generateCertificate(rawValue), null);
    }

    private X509Certificate generateCertificate(String certData) throws CertificateException, IOException {
        try (InputStream in = new ByteArrayInputStream(decodeHeader(certData))) {
            return (X509Certificate) this.certificateFactory.generateCertificate(in);
        }
    }

    /**
     * Decodes a header value in either of the two supported raw-certificate formats:
     * <ol>
     *   <li>Plain base64-encoded DER (e.g. CF Gorouter {@code xfcc_format: raw}) -- tried first.</li>
     *   <li>URL-encoded PEM (e.g. nginx {@code $ssl_client_escaped_cert}, Envoy XFCC {@code Cert=}/
     *       {@code Chain=}, both documented as "URL encoded PEM format") -- the fallback below.</li>
     * </ol>
     * The fallback is safe to round-trip through a {@code String} as UTF-8: PEM is armored ASCII
     * text (base64 body plus {@code -----BEGIN/END-----} lines), never raw binary DER, so
     * URL-decoding it and re-encoding as UTF-8 cannot lose or alter a byte. Base64 is tried first
     * specifically so a raw DER header (whose base64 alphabet never collides with PEM's
     * {@code -}/space/newline or their percent-escaped forms) is never routed through this
     * String-based fallback.
     */
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

}
