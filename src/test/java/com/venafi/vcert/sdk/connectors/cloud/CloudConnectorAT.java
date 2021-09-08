package com.venafi.vcert.sdk.connectors.cloud;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import com.venafi.vcert.sdk.policy.domain.*;
import com.venafi.vcert.sdk.utils.VCertConstants;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertClient;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.VCertUtils;

import feign.FeignException;

class CloudConnectorAT {

    private CloudConnector classUnderTest;

    @BeforeEach
    public void authenticate() throws VCertException {
        Security.addProvider(new BouncyCastleProvider());
        Cloud cloud = Cloud.connect(System.getenv("CLOUDURL"));
        classUnderTest = new CloudConnector(cloud);
        Authentication authentication = new Authentication(null, null, System.getenv("APIKEY"));
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            classUnderTest.readZoneConfiguration(System.getenv("CLOUDZONE"));
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }

    @Test
    void generateRequest() throws VCertException, IOException {
        String zoneName = System.getenv("CLOUDZONE");
        String commonName = TestUtils.randomCN();
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        assertThat(certificateRequest.csr()).isNotEmpty();

        PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(
                new StringReader(Strings.fromByteArray(certificateRequest.csr()))).readObject();

        String subject = request.getSubject().toString();
        assertThat(subject).contains(String.format("CN=%s", commonName));
        assertThat(subject).contains("O=Venafi\\, Inc.");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=US");
        assertThat(subject).contains("L=SLC");
        assertThat(subject).contains("ST=Utah");
    }

    @Test
    void requestCertificate() throws VCertException, UnknownHostException {
        String zoneName = System.getenv("CLOUDZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);
        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();
    }

    @Test
    void requestCertificateUnrestricted() throws VCertException, UnknownHostException {
        String zoneName = System.getenv("CLOUDZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN()).
                        organizationalUnit(Arrays.asList("DevOps")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA)
                .keyLength(2048);
        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();
    }

    @Test
    void retrieveCertificate() throws VCertException, UnknownHostException {
        String zoneName = System.getenv("CLOUDZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();

        certificateRequest.pickupId(certificateId);
        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);

        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.chain()).hasSize(2);
        assertThat(pemCollection.privateKey()).isNotNull();
    }

    @Test
    void revokeCertificate() throws VCertException {
        assertThrows(UnsupportedOperationException.class, () -> {
            classUnderTest.revokeCertificate(new RevocationRequest());
        });
    }

    @Test
    void renewCertificate() throws VCertException, UnknownHostException,
            CertificateException {
        String zoneName = System.getenv("CLOUDZONE");
        String commonName = TestUtils.randomCN();
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();

        certificateRequest.pickupId(certificateId);

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);
        X509Certificate cert = (X509Certificate) pemCollection.certificate();

        String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();

        CertificateRequest certificateRequestToRenew = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);
        classUnderTest.generateRequest(zoneConfiguration, certificateRequestToRenew);

        String renewRequestId = classUnderTest.renewCertificate(
                new RenewalRequest().request(certificateRequestToRenew).thumbprint(thumbprint));

        assertThat(renewRequestId).isNotNull();
    }

    @Test
    void importCertificate() {
        assertThrows(UnsupportedOperationException.class,
                () -> classUnderTest.importCertificate(new ImportRequest()));
    }

    @Test
    void readPolicyConfiguration() {
        assertThrows(UnsupportedOperationException.class,
                () -> classUnderTest.readPolicyConfiguration("zone"));
    }

    @Test
    @DisplayName("Create a certificate and validate specified validity hours - Cloud")
    public void createCertificateValidateValidityHours() throws VCertException {

        String zone = System.getenv(TestUtils.CLOUD_ZONE);
        String apiKey = System.getenv(TestUtils.API_KEY);

        String commonName = TestUtils.randomCN();

        final Authentication auth = Authentication.builder()
                .apiKey(apiKey)
                .build();

        final Config config = Config.builder()
                .connectorType(ConnectorType.CLOUD)
                .build();

        final VCertClient client = new VCertClient(config);
        client.authenticate(auth);

        CertificateRequest certificateRequest = new CertificateRequest().subject(
                new CertificateRequest.PKIXName()
                        .commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Arrays.asList("DevOps"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("Salt Lake City"))
                        .province(Collections.singletonList("Utah")))
                .keyType(KeyType.RSA)
                .validityHours(TestUtils.VALID_HOURS);

        ZoneConfiguration zoneConfiguration = client.readZoneConfiguration(zone);
        certificateRequest = client.generateRequest(zoneConfiguration, certificateRequest);

        // Submit the certificate request
        client.requestCertificate(certificateRequest, zoneConfiguration);

        // Retrieve PEM collection from Venafi
        PEMCollection pemCollection = client.retrieveCertificate(certificateRequest);

        Date notAfter = pemCollection.certificate().getNotAfter();
        LocalDate notAfterDate = notAfter.toInstant().atOffset(ZoneOffset.UTC).toLocalDate();


        Instant now = Instant.now();
        LocalDateTime utcDateTime = LocalDateTime.ofInstant(now, ZoneOffset.UTC);

        int validityDays = VCertUtils.getValidityDays(TestUtils.VALID_HOURS);
        utcDateTime = utcDateTime.plusDays(validityDays);

        LocalDate nowDateInUTC = utcDateTime.toLocalDate();

        //Dates should be equals if not then it will fail
        assertTrue(notAfterDate.compareTo(nowDateInUTC) == 0);

    }

    @Test
    @DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods")
    public void createAndGetPolicy() throws VCertException {

        String policyName = CloudTestUtils.getRandomZone();

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        classUnderTest.setPolicy(policyName, policySpecification);

        PolicySpecification policySpecificationReturned = classUnderTest.getPolicy(policyName);

        //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
        //due it doesn't contain it
        policySpecification.name(policySpecificationReturned.name());
        //The returned policySpecification will contains the default cloud CA, then it will needed
        //to set it to the policySpecification source
        policySpecification.policy().certificateAuthority(VCertConstants.CLOUD_DEFAULT_CA);

        assertEquals(policySpecification, policySpecificationReturned);
    }

    @Test
    @DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods for Entrust CA")
    public void createAndGetPolicyForEntrust() throws VCertException {

        String policyName = CloudTestUtils.getRandomZone();

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
        policySpecification.policy().certificateAuthority(TestUtils.CLOUD_ENTRUST_CA_NAME);

        classUnderTest.setPolicy(policyName, policySpecification);

        PolicySpecification policySpecificationReturned = classUnderTest.getPolicy(policyName);

        //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
        //due it doesn't contain it
        policySpecification.name(policySpecificationReturned.name());

        assertEquals(policySpecification, policySpecificationReturned);
    }

    @Test
    @DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods for Digicert CA")
    public void createAndGetPolicyForDigicert() throws VCertException {

        String policyName = CloudTestUtils.getRandomZone();

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
        policySpecification.policy().certificateAuthority(TestUtils.CLOUD_DIGICERT_CA_NAME);

        classUnderTest.setPolicy(policyName, policySpecification);

        PolicySpecification policySpecificationReturned = classUnderTest.getPolicy(policyName);
        
        //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
        //due it doesn't contain it
        policySpecification.name(policySpecificationReturned.name());

        assertEquals(policySpecification, policySpecificationReturned);
    }
}
