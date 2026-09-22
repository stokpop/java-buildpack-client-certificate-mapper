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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class XfccResolverTest {

    private static final String HASH = "078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b";

    /**
     * An over-escaped URL-encoded PEM: every {@code -} is written {@code %2D}. Real nginx
     * ({@code $ssl_client_escaped_cert}) and Envoy leave {@code -} literal, since both escape only
     * outside the RFC 3986 unreserved set -- that form is covered by
     * {@link #envoyUrlEncodedPemCertificateIsDecoded()}. Kept as the fixture because a value that
     * escapes more than it must is the harder input to decode, and routers do vary.
     */
    private static final String NGINX_ESCAPED_CERT = "" +
        "%2D%2D%2D%2D%2DBEGIN%20CERTIFICATE%2D%2D%2D%2D%2D%0D%0AMIIDLTCCA" +
        "hWgAwIBAgIkMDg3ZjVmZGMtOThkNy00MGMwLTY0ZDMtZmQ5NWFmODMx%0D%0AOTh" +
        "kMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD2NyZWRodWJDbGllbnRDQTAe%0D" +
        "%0AFw0xNzA1MDIwMDQ5MzFaFw0xNzA1MDMwMDQ5MzFaMGIxMTAvBgNVBAsTKGFwc" +
        "Doy%0D%0AMzI4MmZkMS0zNWI0LTQ1ZGQtYTYwMi04Zjc2ZjRhNjBkMTExLTArBgN" +
        "VBAMTJDA4%0D%0AN2Y1ZmRjLTk4ZDctNDBjMC02NGQzLWZkOTVhZjgzMTk4ZDCCA" +
        "SIwDQYJKoZIhvcN%0D%0AAQEBBQADggEPADCCAQoCggEBAPhcSn56pIVWI0Rpwrk" +
        "C3WcvumLw%2B3i%2Foj3YBbEx%0D%0AAUAFJMFl%2Fyt1zpAghLvYOOiiUS%2FW0" +
        "4SKp8Z9FHlmNabJOzV40RIciSbYCW0tBeFG%0D%0AKNkgolTGamvRLZkkHUJdywE" +
        "QkvnMG7%2B2XczDBoCZ7fdBepg6gieSqGhQwl%2FsO7x%2F%0D%0ATouvQnujKwJ" +
        "LiXOKQq00TkT%2BMVEzOZyOMlqFh9r2XjUGuh1HnRM0IAj6buR5663t%0D%0A4lA" +
        "QqOluTAVNCKWSrAMIKb0G4QPTQ4pKRTeMEnTijFErtKlpzc64HYrBpufj1K%2Fq%" +
        "0D%0ATxYIy3EgeT3UVSclSub14M4%2Fr%2FmOmWotYP81BR1Ko7pxV28CAwEAAaM" +
        "TMBEwDwYD%0D%0AVR0RBAgwBocECv4AAjANBgkqhkiG9w0BAQsFAAOCAQEAuG8A3" +
        "3%2BUn2rvXA%2BqAf40%0D%0AgBponN2mjx0drasw%2FMqBnclUL1MYvOepqcGxx" +
        "NB%2F1Ok%2FbKKDMr03ugVaxzAdoknA%0D%0ANwIyY%2FghL6xHs%2FJrmuSGDs9" +
        "BeNF0y8TOpQmmjh1EDFtR9YFuTRP1OZ6XBf5fbd80%0D%0AQ684k%2FWu8ELywZJ" +
        "d53FKcTPJRQ%2FYjn4QFJORtcNFlvMFWTmJLLiMDbI8JBcqMLZH%0D%0AsgdyBtV" +
        "7kJdZU3nszgFEPspYzFfxQZmq6V%2BpJb%2BdmG2jYWrX%2FR21J9x1dJHBCoPp%" +
        "0D%0AXcqQm8pYsDxi%2BHTGS6an78sHqrvU5uQJq2MW8o6iBJR80bFgWSl7GTqK3" +
        "Xz5iTxU%0D%0AEw%3D%3D%0D%0A%2D%2D%2D%2D%2DEND%20CERTIFICATE%2D%2" +
        "D%2D%2D%2D%0D%0A";

    @Test
    public void unknownProviderFallsBackToPlatformDefault() throws Exception {
        XfccResolver resolver = new XfccResolver(null, "NoSuchProviderXyz");

        ParsedXfcc parsed = resolver.resolve(NGINX_ESCAPED_CERT);

        assertThat(parsed.certificate()).isNotNull();
    }

    @Test
    public void providerWithoutX509FallsBackToPlatformDefault() throws Exception {
        // SunJCE is always registered but offers no X.509 CertificateFactory, like providers that
        // only accelerate ciphers and digests (e.g. Amazon Corretto Crypto Provider).
        XfccResolver resolver = new XfccResolver(null, "SunJCE");

        ParsedXfcc parsed = resolver.resolve(NGINX_ESCAPED_CERT);

        assertThat(parsed.certificate()).isNotNull();
    }

    @Test
    public void namedProviderIsUsedWhenRegistered() throws Exception {
        XfccResolver resolver = new XfccResolver(null, "SUN");

        ParsedXfcc parsed = resolver.resolve(NGINX_ESCAPED_CERT);

        assertThat(parsed.certificate()).isNotNull();
    }

    @Test
    public void identityOnlyXfccIsAlsoCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Subject=\"/CN=client\"";

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNull();
        assertThat(first.cfSubjectDn()).isNotNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second).isSameAs(first);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void xfccWithCertIsCachedAcrossCalls() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Cert=" + NGINX_ESCAPED_CERT;

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNotNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second.certificate()).isSameAs(first.certificate());
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void rawNonXfccCertificateIsDecodedAndCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);

        ParsedXfcc parsed = resolver.resolve(NGINX_ESCAPED_CERT);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.cfSubjectDn()).isNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
    }

    /**
     * Covers the other of the two supported raw-certificate formats: plain base64-encoded DER
     * (no PEM armor, no URL-encoding), as produced e.g. by CF Gorouter's {@code xfcc_format: raw}.
     * {@code decodeHeader} detects the format instead of trying decoders in turn: a value with no
     * percent sign and no PEM armor is base64 DER, so this exercises the base64 branch exclusively
     * and confirms it never touches the URL-decode/UTF-8 path.
     */
    @Test
    public void rawBase64DerCertificateIsDecodedAndMatchesPemEquivalent() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(expected.getEncoded());

        ParsedXfcc parsed = resolver.resolve(rawBase64Der);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
        assertThat(parsed.certificate().getSerialNumber()).isEqualTo(expected.getSerialNumber());
    }

    /**
     * Confirms the URL-encoded-PEM branch of {@code decodeHeader} round-trips the DER bytes
     * byte-for-byte: PEM is armored ASCII text (base64 body + header/footer lines), so decoding
     * the URL-encoding and re-encoding as UTF-8 cannot lose or alter any byte, unlike a raw binary
     * DER payload would. This is asserted here by comparing against a certificate decoded straight
     * from base64 DER with no PEM/URL-encoding step at all.
     */
    @Test
    public void urlEncodedPemCertificateMatchesRawDerByteForByte() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));

        X509Certificate viaPem = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(viaPem.getEncoded());
        X509Certificate viaRawDer = resolver.resolve(rawBase64Der).certificate();

        assertThat(viaPem.getEncoded()).isEqualTo(viaRawDer.getEncoded());
    }

    @Test
    public void xfccCertFieldAcceptsRawBase64DerAsWellAsUrlEncodedPem() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(expected.getEncoded());

        ParsedXfcc parsed = resolver.resolve("Hash=" + HASH + ";Cert=" + rawBase64Der);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
    }

    @Test
    public void chainOnlyXfccYieldsNoCertificateButIsStillCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Chain=" + NGINX_ESCAPED_CERT;

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second).isSameAs(first);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void resolveWorksWithCachingDisabled() throws Exception {
        XfccResolver resolver = new XfccResolver(null);

        ParsedXfcc parsed = resolver.resolve("Hash=" + HASH + ";Cert=" + NGINX_ESCAPED_CERT);

        assertThat(resolver.cache()).isNull();
        assertThat(parsed.certificate()).isNotNull();
    }
    /**
     * PEM that reaches the filter without URL-encoding at all. The armor is detected directly, so
     * the value never goes near the base64 or URL-decode branches.
     */
    @Test
    public void unencodedPemCertificateIsDecoded() throws Exception {
        XfccResolver resolver = new XfccResolver(null);
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String pem = pem(Base64.getEncoder().encodeToString(expected.getEncoded()), "\n");

        ParsedXfcc parsed = resolver.resolve(pem);

        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
    }

    /**
     * Envoy encodes its {@code Cert=} PEM with {@link java.net.URLEncoder}, which leaves {@code -}
     * literal and turns the space in {@code BEGIN CERTIFICATE} into {@code +}. nginx percent-encodes
     * the dashes instead ({@link #NGINX_ESCAPED_CERT}); both must decode to the same DER.
     */
    @Test
    public void envoyUrlEncodedPemCertificateIsDecoded() throws Exception {
        XfccResolver resolver = new XfccResolver(null);
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String encoded = URLEncoder.encode(pem(Base64.getEncoder().encodeToString(expected.getEncoded()), "\n"),
                StandardCharsets.UTF_8.name());

        ParsedXfcc parsed = resolver.resolve("Hash=" + HASH + ";Cert=" + encoded);

        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
    }

    /**
     * A value that is neither base64 nor PEM still fails the way it always has: the bytes reach
     * {@code CertificateFactory}, which rejects them, rather than escaping as some other exception.
     */
    @Test
    public void unrecognisedCertificateValueStillFailsAsCertificateException() throws Exception {
        XfccResolver resolver = new XfccResolver(null);

        assertThatThrownBy(() -> resolver.resolve("Hash=" + HASH + ";Cert=not%20a%20certificate"))
                .isInstanceOf(CertificateException.class);
    }

    /** A PEM that arrived with no line breaks at all, which a header can carry unencoded. */
    @Test
    public void singleLinePemCertificateIsDecoded() throws Exception {
        XfccResolver resolver = new XfccResolver(null);
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String base64 = Base64.getEncoder().encodeToString(expected.getEncoded());

        ParsedXfcc parsed = resolver.resolve("-----BEGIN CERTIFICATE-----" + base64 + "-----END CERTIFICATE-----");

        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
    }

    /**
     * A PEM body carrying a character that is neither base64 nor whitespace is corrupt. A MIME
     * decoder skips such characters and would hand back the original DER, so the corruption must
     * be rejected here -- and not recovered by {@code CertificateFactory}'s own lenient PEM reader.
     */
    @Test
    public void pemWithIllegalCharacterInBodyIsRejected() throws Exception {
        XfccResolver resolver = new XfccResolver(null);
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String base64 = Base64.getEncoder().encodeToString(expected.getEncoded());
        String corrupt = pem(base64.substring(0, 100) + "*" + base64.substring(100), "\n");

        assertThatThrownBy(() -> resolver.resolve(corrupt))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    public void urlEncodedPemWithIllegalCharacterInBodyIsRejected() throws Exception {
        XfccResolver resolver = new XfccResolver(null);
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String base64 = Base64.getEncoder().encodeToString(expected.getEncoded());
        String encoded = URLEncoder.encode(pem(base64.substring(0, 100) + "*" + base64.substring(100), "\n"),
                StandardCharsets.UTF_8.name());

        assertThatThrownBy(() -> resolver.resolve("Hash=" + HASH + ";Cert=" + encoded))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    public void providerNameReportsTheProviderInUse() throws Exception {
        String platformDefault = CertificateFactory.getInstance("X.509").getProvider().getName();

        assertThat(new XfccResolver(null).providerName()).isEqualTo(platformDefault);
        assertThat(new XfccResolver(null, "SUN").providerName()).isEqualTo("SUN");
        assertThat(new XfccResolver(null, "NoSuchProviderXyz").providerName()).isEqualTo(platformDefault);
        assertThat(new XfccResolver(null, "SunJCE").providerName()).isEqualTo(platformDefault);
    }

    /**
     * BouncyCastle's {@code CertificateFactory} keeps per-parse state in unsynchronized instance
     * fields, and a PKCS#7 {@code SignedData} input parks its certificate set there. One resolver
     * serves every request thread, so it must not share a factory instance across threads: a
     * concurrent PKCS#7 value must never break or alter the parse of an ordinary certificate.
     */
    @Test
    public void concurrentParsesOnANonThreadSafeProviderDoNotInterfere() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        try {
            XfccResolver resolver = new XfccResolver(null, "BC");
            X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
            String plain = Base64.getEncoder().encodeToString(expected.getEncoded());
            String pkcs7 = Base64.getEncoder().encodeToString(pkcs7(expected.getEncoded()));

            int threads = 8;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            AtomicLong plainFailures = new AtomicLong();
            AtomicReference<Throwable> firstFailure = new AtomicReference<>();
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
            try {
                List<Future<?>> workers = new ArrayList<>();
                for (int t = 0; t < threads; t++) {
                    boolean parsesPlain = t % 2 == 0;
                    workers.add(pool.submit(() -> {
                        while (System.nanoTime() < end) {
                            if (!parsesPlain) {
                                try {
                                    resolver.resolve(pkcs7);
                                } catch (Exception e) {
                                    // Only the ordinary certificate's outcome is under test.
                                }
                                continue;
                            }
                            try {
                                X509Certificate actual = resolver.resolve(plain).certificate();
                                if (actual == null || !Arrays.equals(actual.getEncoded(), expected.getEncoded())) {
                                    plainFailures.incrementAndGet();
                                }
                            } catch (Exception e) {
                                plainFailures.incrementAndGet();
                                firstFailure.compareAndSet(null, e);
                            }
                        }
                    }));
                }
                for (Future<?> worker : workers) {
                    worker.get();
                }
            } finally {
                pool.shutdownNow();
            }

            assertThat(plainFailures.get())
                    .as("ordinary certificate parses that failed or returned another certificate; first failure: %s",
                            firstFailure.get())
                    .isZero();
        } finally {
            Security.removeProvider("BC");
        }
    }

    /** A certs-only PKCS#7 {@code SignedData} carrying {@code der}, as {@code openssl crl2pkcs7} emits. */
    private static byte[] pkcs7(byte[] der) throws Exception {
        SignedData signedData = new SignedData(new ASN1Integer(1), new DERSet(),
                new ContentInfo(PKCSObjectIdentifiers.data, null), new DERSet(ASN1Primitive.fromByteArray(der)),
                null, new DERSet());
        return new ContentInfo(PKCSObjectIdentifiers.signedData, signedData).getEncoded();
    }

    private static String pem(String base64, String lineEnding) {
        StringBuilder pem = new StringBuilder("-----BEGIN CERTIFICATE-----").append(lineEnding);
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append(lineEnding);
        }
        return pem.append("-----END CERTIFICATE-----").append(lineEnding).toString();
    }
}
