package com.venafi.vcert.sdk.connectors.cloud;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import feign.FeignException;
import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;

class CloudConnectorAT {

  private CloudConnector classUnderTest;

  @BeforeEach
  public void authenticate() throws VCertException {
    Security.addProvider(new BouncyCastleProvider());
    Cloud cloud = Cloud.connect(System.getenv("CLOUDURL"));
    classUnderTest = new CloudConnector(cloud);
    Authentication authentication = new Authentication(null, null, System.getenv("TOKEN"));
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
  void requestCertificate() throws VCertException, SocketException, UnknownHostException {
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
  void retrieveCertificate() throws VCertException, SocketException, UnknownHostException {
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
  void renewCertificate() throws VCertException, UnknownHostException, SocketException,
      CertificateException, NoSuchAlgorithmException {
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
}
