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

package org.cloudfoundry.router;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
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

    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";

    private static final String PEM_END = "-----END CERTIFICATE-----";

    private final CertificateFactory certificateFactory;

    /** {@code null} when caching is disabled. */
    private final CertificateCache certificateCache;

    /** @param certificateCache the cache to use, or {@code null} to disable caching */
    public XfccResolver(CertificateCache certificateCache) throws CertificateException {
        this(certificateCache, null);
    }

    /**
     * @param certificateCache the cache to use, or {@code null} to disable caching
     * @param providerName the JCA provider to parse certificates with, or {@code null} to let the
     *        JCA pick the first registered provider offering {@code CertificateFactory.X.509}.
     *        A named provider that is not registered is logged and ignored, so a misconfigured
     *        property degrades to the default rather than failing the filter.
     *
     * <p>With {@code null} the provider follows the JVM's provider order, so an application that
     * calls {@code Security.insertProviderAt(new BouncyCastleProvider(), 1)} moves this filter to
     * BouncyCastle with no configuration here. {@code Security.addProvider} appends instead, which
     * leaves parsing on the platform default. Naming a provider overrides that order in both
     * directions.
     *
     * <p>Naming a provider matters for deployments that parse many distinct certificates. The
     * default {@code SUN} provider takes a lock on every lookup of its own certificate cache in
     * {@code sun.security.provider.X509Factory}, so concurrent parsing serializes: measured on four
     * threads, ~46% of thread time blocked, and four cores returning 1.4x the throughput of one
     * rather than 4x. A provider with no such cache, such as BouncyCastle, returns ~2.9x. JDK 27
     * narrows the lock but does not remove it. See {@code docs/PERFORMANCE.md}.
     */
    public XfccResolver(CertificateCache certificateCache, String providerName) throws CertificateException {
        this.certificateFactory = certificateFactory(providerName);
        this.certificateCache = certificateCache;
    }

    private static CertificateFactory certificateFactory(String providerName) throws CertificateException {
        if (providerName == null || providerName.trim().isEmpty()) {
            return CertificateFactory.getInstance("X.509");
        }
        try {
            return CertificateFactory.getInstance("X.509", providerName.trim());
        } catch (NoSuchProviderException e) {
            LOGGER.warning("JCA provider '" + providerName.trim() + "' is not registered; parsing certificates with the"
                + " platform default provider instead. Register the provider in the application before the filter"
                + " starts, or unset org.cloudfoundry.router.certificate.provider.");
        } catch (CertificateException e) {
            // A registered provider that offers no X.509 CertificateFactory, e.g. one that only
            // accelerates ciphers and digests. Degrade rather than fail the filter's construction.
            LOGGER.warning("JCA provider '" + providerName.trim() + "' does not provide an X.509 CertificateFactory;"
                + " parsing certificates with the platform default provider instead.");
        }
        return CertificateFactory.getInstance("X.509");
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

    /**
     * The XFCC fields of {@code rawValue} without its certificate: the entry and any
     * {@link CfSubjectDn}, never a decoded {@code Cert=}.
     *
     * <p>For the failure path. {@link #resolve(String)} decodes the certificate while building its
     * bundle, so a corrupt {@code Cert=} throws before the caller sees any of the entry -- yet the
     * {@code Hash=} and {@code Subject=} fields the router vouched for are intact and independent of
     * the certificate blob. Callers publish those from here before letting the failure propagate,
     * so an application that authorizes on the CF identity is not left unable to distinguish a
     * corrupt certificate from a request that carried no client certificate at all.
     *
     * <p>Nothing is cached: this runs only when a parse has already failed.
     */
    public ParsedXfcc identity(String rawValue) {
        XfccEntry xfcc = new XfccEntry(rawValue);
        if (!xfcc.resemblesXfcc() || !xfcc.hasField(XfccField.SUBJECT)) {
            return new ParsedXfcc(xfcc, null, null);
        }
        return new ParsedXfcc(xfcc, null, XfccHeaderParser.parseCfSubjectDn(xfcc.get(XfccField.SUBJECT)));
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
     *   <li>Plain base64-encoded DER (e.g. CF Gorouter {@code xfcc_format: raw}).</li>
     *   <li>PEM, usually URL-encoded (e.g. nginx {@code $ssl_client_escaped_cert}, Envoy XFCC
     *       {@code Cert=}/{@code Chain=}, both documented as "URL encoded PEM format").</li>
     * </ol>
     * The format is detected rather than discovered by trial: a percent sign means the value is
     * URL-encoded (base64 has none), and a leading {@code -} means unencoded PEM. Decoding PEM to
     * DER here rather than handing the armored text to {@link CertificateFactory} is what makes
     * this path cheap -- the platform factory reads armored input roughly 18x slower than it reads
     * the same certificate as DER, even when its own certificate cache serves the result.
     *
     * <p>Round-tripping PEM through a {@code String} as UTF-8 is safe: PEM is armored ASCII text
     * (base64 body plus {@code -----BEGIN/END-----} lines), never raw binary DER, so URL-decoding
     * it cannot lose or alter a byte. A value that matches neither format falls through to the
     * previous behaviour, which leaves the resulting bytes for {@code CertificateFactory} to
     * reject.
     */
    private byte[] decodeHeader(String rawCertificate) {
        if (startsWithPemArmor(rawCertificate)) {
            byte[] der = pemToDer(rawCertificate);
            if (der != null) {
                return der;
            }
        }
        if (rawCertificate.indexOf('%') >= 0) {
            String decoded = urlDecode(rawCertificate);
            byte[] der = pemToDer(decoded);
            if (der != null) {
                return der;
            }
            return decoded.getBytes(StandardCharsets.UTF_8);
        }
        try {
            return Base64.getDecoder().decode(rawCertificate);
        } catch (IllegalArgumentException e) {
            return urlDecode(rawCertificate).getBytes(StandardCharsets.UTF_8);
        }
    }

    private static boolean startsWithPemArmor(String value) {
        int i = 0;
        while (i < value.length() && Character.isWhitespace(value.charAt(i))) {
            i++;
        }
        return value.startsWith(PEM_BEGIN, i);
    }

    /**
     * Extracts the DER bytes of the first certificate in a PEM document, or {@code null} when the
     * value carries no complete {@code -----BEGIN/END CERTIFICATE-----} block or its body is not
     * valid base64. Callers treat {@code null} as "not PEM" and fall back.
     */
    private static byte[] pemToDer(String pem) {
        int begin = pem.indexOf(PEM_BEGIN);
        if (begin < 0) {
            return null;
        }
        int bodyStart = begin + PEM_BEGIN.length();
        int end = pem.indexOf(PEM_END, bodyStart);
        if (end < 0) {
            return null;
        }
        try {
            // A MIME decoder because it skips the line breaks in the body, whatever the router
            // wrapped them with -- including a PEM that arrived with no line breaks at all.
            return Base64.getMimeDecoder().decode(pem.substring(bodyStart, end));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, "utf-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Header contains value that is neither base64 nor url encoded");
        }
    }
}
