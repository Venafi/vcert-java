package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.net.*;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class CertificateRequestTest {

    @Test
    void generateECDSAPrivateKey() {
        Security.addProvider(new BouncyCastleProvider());

        assertThatCode(() -> {
            CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());
            KeyPair keyPair = certificateRequest.generateECDSAKeyPair(EllipticCurve.EllipticCurveP224);
            verifyKeyPair(keyPair, SignatureAlgorithm.ECDSAWithSHA256.standardName());
        }).doesNotThrowAnyException();
    }

    @Test
    void generateRSAKeyPair() {
        assertThatCode(() -> {
            CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());
            KeyPair keyPair = certificateRequest.generateRSAKeyPair(512);
            verifyKeyPair(keyPair, SignatureAlgorithm.SHA256WithRSA.standardName());
        }).doesNotThrowAnyException();
    }

    @Test
    void generateCertificateRequestWithRSAKey() throws IOException, VCertException {
        Security.addProvider(new BouncyCastleProvider());

        CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());

        certificateRequest.keyType(KeyType.RSA);
        certificateRequest.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);

        certificateRequest.generatePrivateKey();
        certificateRequest.generateCSR();

        PKCS10CertificationRequest cert = getCertRequest(certificateRequest);

        String subject = cert.getSubject().toString();
        assertThat(subject).contains("CN=vcert.test.vfidev.com");
        assertThat(subject).contains("O=Venafi\\, Inc.");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=US");
        assertThat(subject).contains("L=SLC");
        assertThat(subject).contains("ST=Utah");

        // TODO verify certificate is valid
    }

    @Test
    void generateCertificateRequestWithECDSAKey() throws VCertException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());

        certificateRequest.keyType(KeyType.ECDSA);
        certificateRequest.keyCurve(EllipticCurve.EllipticCurveP256);
        certificateRequest.signatureAlgorithm(SignatureAlgorithm.ECDSAWithSHA256);

        certificateRequest.generatePrivateKey();
        certificateRequest.generateCSR();

        PKCS10CertificationRequest cert = getCertRequest(certificateRequest);

        String subject = cert.getSubject().toString();
        assertThat(subject).contains("CN=vcert.test.vfidev.com");
        assertThat(subject).contains("O=Venafi\\, Inc.");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=US");
        assertThat(subject).contains("L=SLC");
        assertThat(subject).contains("ST=Utah");

        // TODO verify certificate is valid

    }

    private PKCS10CertificationRequest getCertRequest(CertificateRequest certificateRequest) throws IOException {
        StringReader reader = new StringReader(new String(certificateRequest.csr()));
        try(PEMParser pemParser = new PEMParser(reader)) {
            return (PKCS10CertificationRequest)pemParser.readObject();
        }
    }

    private CertificateRequest generateTestCertificateRequest(Collection<InetAddress> ips) throws UnknownHostException {
        return new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName("vcert.test.vfidev.com")
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(ips);
    }

    private Collection<InetAddress> getTestIps() throws SocketException {
        Collection<InetAddress> ips = new ArrayList<>();
        for(NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            for(InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                if(!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                    ips.add(inetAddress);
                }
            }
        }
        return ips;
    }

    private void verifyKeyPair(KeyPair keyPair, String signatureName) throws Exception {
        byte[] challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge);

        Signature sig = Signature.getInstance(signatureName, "BC");
        sig.initSign(keyPair.getPrivate());
        sig.update(challenge);
        byte[] signature = sig.sign();

        sig.initVerify(keyPair.getPublic());
        sig.update(challenge);

        assertThat(sig.verify(signature)).isTrue();
    }
}
