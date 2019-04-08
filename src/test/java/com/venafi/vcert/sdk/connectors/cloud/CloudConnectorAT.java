package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static com.venafi.vcert.sdk.TestUtils.getTestIps;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CloudConnectorAT {

    private CloudConnector classUnderTest;

    @BeforeEach
    public void authenticate() throws VCertException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cloud cloud = Cloud.connect(System.getenv("VENAFI_CLOUD_URL"));
        classUnderTest = new CloudConnector(cloud);
        Authentication authentication = new Authentication(null, null, System.getenv("VENAFI_API_KEY"));
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(System.getenv("VENAFI_ZONE"));
        } catch(FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }

    @Test
    void ping() throws VCertException {
        assertThatCode(() -> classUnderTest.ping()).doesNotThrowAnyException();
    }

    @Test
    void generateRequest() throws VCertException, IOException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        assertThat(certificateRequest.csr()).isNotEmpty();

        PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(new StringReader(new String(certificateRequest.csr()))).readObject();

        String subject = request.getSubject().toString();
        assertThat(subject).contains("O=Venafi, Inc.");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=US");
        assertThat(subject).contains("L=SLC");
        assertThat(subject).contains("P=Utah");

    }

    @Test
    void requestCertificate() throws VCertException, SocketException, UnknownHostException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();
    }

    @Test
    void retrieveCertificate() throws VCertException, SocketException, UnknownHostException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();

        certificateRequest.pickupId(certificateId);
        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);

        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.chain()).hasSize(2);
        assertThat(pemCollection.privateKey()).isNull();
    }

    @Test
    void revokeCertificate() throws VCertException {
        assertThrows(UnsupportedOperationException.class, () -> {
            classUnderTest.revokeCertificate(new RevocationRequest());
        });
    }

    @Test
    void renewCertificate() throws VCertException, UnknownHostException, SocketException, CertificateException, NoSuchAlgorithmException {
        String zone = System.getenv("VENAFI_ZONE");
        String commonName = System.getenv("VENAFI_CERT_COMMON_NAME");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zone);
        assertThat(certificateId).isNotNull();

        certificateRequest.pickupId(certificateId);

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);
        X509Certificate cert = (X509Certificate) pemCollection.certificate();

        String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();

        CertificateRequest certificateRequestToRenew = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps())
                .keyType(KeyType.RSA);
        classUnderTest.generateRequest(zoneConfiguration, certificateRequestToRenew);

        String renewRequestId = classUnderTest.renewCertificate(new RenewalRequest()
                .request(certificateRequestToRenew)
                .thumbprint(thumbprint));

        assertThat(renewRequestId).isNotNull();
    }

    @Test
    void importCertificate() {
        assertThrows(UnsupportedOperationException.class, () -> classUnderTest.importCertificate(new ImportRequest()));
    }

    @Test
    void readPolicyConfiguration() {
        assertThrows(UnsupportedOperationException.class, () -> classUnderTest.readPolicyConfiguration("zone"));
    }
}