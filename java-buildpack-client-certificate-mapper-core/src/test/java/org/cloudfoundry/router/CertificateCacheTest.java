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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public final class CertificateCacheTest {

    @SuppressWarnings("deprecation")
    private static X509Certificate fakeCert() {
        return new X509Certificate() {
            @Override public void checkValidity() {}
            @Override public void checkValidity(Date date) {}
            @Override public int getVersion() { return 3; }
            @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
            @Override public Principal getIssuerDN() { return () -> "issuer"; }
            @Override public Principal getSubjectDN() { return () -> "subject"; }
            @Override public Date getNotBefore() { return new Date(0); }
            @Override public Date getNotAfter() { return new Date(Long.MAX_VALUE); }
            @Override public byte[] getTBSCertificate() { return new byte[0]; }
            @Override public byte[] getSignature() { return new byte[0]; }
            @Override public String getSigAlgName() { return ""; }
            @Override public String getSigAlgOID() { return ""; }
            @Override public byte[] getSigAlgParams() { return new byte[0]; }
            @Override public boolean[] getIssuerUniqueID() { return new boolean[0]; }
            @Override public boolean[] getSubjectUniqueID() { return new boolean[0]; }
            @Override public boolean[] getKeyUsage() { return new boolean[0]; }
            @Override public int getBasicConstraints() { return -1; }
            @Override public byte[] getEncoded() { return new byte[0]; }
            @Override public void verify(PublicKey key) {}
            @Override public void verify(PublicKey key, String provider) {}
            @Override public String toString() { return "fakeCert"; }
            @Override public PublicKey getPublicKey() { return null; }
            @Override public boolean hasUnsupportedCriticalExtension() { return false; }
            @Override public Set<String> getCriticalExtensionOIDs() { return null; }
            @Override public Set<String> getNonCriticalExtensionOIDs() { return null; }
            @Override public byte[] getExtensionValue(String oid) { return new byte[0]; }
        };
    }

    @Test
    public void getMissReturnsNull() {
        CertificateCache cache = new CertificateCache(10);
        assertThat(cache.get("missing")).isNull();
    }

    @Test
    public void putAndGetReturnsSameInstance() {
        CertificateCache cache = new CertificateCache(10);
        X509Certificate cert = fakeCert();
        cache.put("key1", cert);
        assertThat(cache.get("key1")).isSameAs(cert);
    }

    @Test
    public void entryInPreviousGenerationIsStillReturned() {
        CertificateCache cache = new CertificateCache(2);
        X509Certificate cert = fakeCert();
        cache.put("key1", cert);
        // fill current gen to trigger rotation
        cache.put("key2", fakeCert());
        cache.put("key3", fakeCert()); // triggers rotation: key1 moves to prevGen
        assertThat(cache.get("key1")).isSameAs(cert);
    }

    @Test
    public void entryEvictedAfterTwoRotations() {
        CertificateCache cache = new CertificateCache(2);
        X509Certificate cert = fakeCert();
        cache.put("key1", cert);
        // first rotation: key1 goes to prevGen
        cache.put("key2", fakeCert());
        cache.put("key3", fakeCert());
        // second rotation: prevGen (with key1) is discarded
        cache.put("key4", fakeCert());
        cache.put("key5", fakeCert());
        assertThat(cache.get("key1")).isNull();
    }

    @Test
    public void countersTrackHitsAndMisses() {
        CertificateCache cache = new CertificateCache(10);
        cache.put("key1", fakeCert());
        cache.get("key1");
        cache.get("key1");
        cache.get("absent");

        assertThat(cache.getHitCount()).isEqualTo(2);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getRotationCount()).isZero();
    }

    @Test
    public void rotationCountIsIncrementedOnEachRotation() {
        CertificateCache cache = new CertificateCache(2);
        cache.put("key1", fakeCert());
        cache.put("key2", fakeCert());
        cache.put("key3", fakeCert()); // first rotation
        cache.put("key4", fakeCert());
        cache.put("key5", fakeCert()); // second rotation

        assertThat(cache.getRotationCount()).isEqualTo(2);
    }

    @Test
    public void statisticsReportsHitRateAndCapacity() {
        CertificateCache cache = new CertificateCache(2);
        cache.put("key1", fakeCert());
        cache.get("key1");
        cache.get("absent");

        assertThat(cache.statistics()).isEqualTo("rotations=0, hits=1, misses=1, hit rate=50%, capacity=4 certificates");
    }

    @Test
    public void statisticsReportsZeroHitRateWithoutLookups() {
        assertThat(new CertificateCache(8).statistics()).isEqualTo("rotations=0, hits=0, misses=0, hit rate=0%, capacity=16 certificates");
    }

    @Test
    public void currentGenEntryTakesPrecedenceOverPreviousGen() {
        CertificateCache cache = new CertificateCache(2);
        X509Certificate oldCert = fakeCert();
        X509Certificate newCert = fakeCert();
        cache.put("key1", oldCert);
        // trigger rotation
        cache.put("key2", fakeCert());
        cache.put("key3", fakeCert());
        // re-add key1 with a new cert in the fresh current gen
        cache.put("key1", newCert);
        assertThat(cache.get("key1")).isSameAs(newCert);
    }

}
