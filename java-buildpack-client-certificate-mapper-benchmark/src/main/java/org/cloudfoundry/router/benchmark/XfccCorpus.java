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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

/**
 * Builds a corpus of distinct, realistic {@code X-Forwarded-Client-Cert} header values.
 *
 * <p>Certificates mimic a Cloud Foundry instance-identity certificate: an RSA 2048 leaf whose
 * Subject DN carries the instance, app, space and organization GUIDs. One key pair is generated
 * and reused across the corpus -- only the Subject DN and serial differ -- so that generating a
 * few hundred distinct certificates stays cheap while every encoded value is byte-for-byte
 * different, which is what the cache keys on.
 */
public final class XfccCorpus {

    /** The header forms this benchmark exercises. */
    public enum Form {

        /** Envoy-style XFCC fields carrying the full certificate as URL-encoded PEM. */
        CERT_FIELD,

        /** A bare base64 DER certificate, as CF Gorouter emits with {@code xfcc_format: raw}. */
        RAW_BASE64,

        /** Envoy-style XFCC fields with no certificate, as CF Gorouter emits on an mTLS domain. */
        IDENTITY_ONLY
    }

    private XfccCorpus() {
    }

    /** Returns {@code count} distinct header values in the requested form. */
    public static String[] build(Form form, int count) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new java.security.SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        // Fixed seed: the corpus is identical from run to run, so results are comparable.
        Random random = new Random(42L);

        String[] headers = new String[count];
        for (int i = 0; i < count; i++) {
            String dn = subjectDn(random);
            X509Certificate certificate = certificate(dn, i, keyPair, signer);
            byte[] der = certificate.getEncoded();
            headers[i] = header(form, dn, der, sha256);
        }
        return headers;
    }

    private static X509Certificate certificate(String dn, int serial, KeyPair keyPair, ContentSigner signer) throws Exception {
        long now = System.currentTimeMillis();
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(serial + 1L),
                new Date(now - 60_000L),
                new Date(now + 86_400_000L),
                name,
                keyPair.getPublic());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static String header(Form form, String dn, byte[] der, MessageDigest sha256) throws Exception {
        String base64 = Base64.getEncoder().encodeToString(der);
        switch (form) {
            case RAW_BASE64:
                return base64;
            case IDENTITY_ONLY:
                return "Hash=" + hex(sha256.digest(der)) + ";Subject=\"" + dn + "\"";
            case CERT_FIELD:
                return "Hash=" + hex(sha256.digest(der)) + ";Subject=\"" + dn + "\""
                        + ";Cert=" + URLEncoder.encode(pem(base64), StandardCharsets.UTF_8.name());
            default:
                throw new IllegalArgumentException("Unsupported form " + form);
        }
    }

    private static String pem(String base64) {
        StringBuilder pem = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        return pem.append("-----END CERTIFICATE-----\n").toString();
    }

    /** A CF instance-identity Subject DN: {@code CN=<instance>,OU=app:<app>,OU=space:<space>,OU=organization:<org>}. */
    private static String subjectDn(Random random) {
        return "CN=" + guid(random)
                + ",OU=app:" + guid(random)
                + ",OU=space:" + guid(random)
                + ",OU=organization:" + guid(random);
    }

    private static String guid(Random random) {
        return new java.util.UUID(random.nextLong(), random.nextLong()).toString();
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

}
