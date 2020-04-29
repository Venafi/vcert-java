package com.venafi.vcert.sdk.connectors.cloud;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.time.OffsetDateTime;
import java.util.Collections;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import com.github.jenspiegsa.wiremockextension.InjectServer;
import com.github.jenspiegsa.wiremockextension.WireMockExtension;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;

@ExtendWith(WireMockExtension.class)
class CloudConnectorIT {

  @InjectServer
  private WireMockServer serverMock;

  private CloudConnector classUnderTest;

  @BeforeEach
  void setup() throws VCertException {
    Security.addProvider(new BouncyCastleProvider());
    classUnderTest = new CloudConnector(Cloud.connect("http://localhost:" + serverMock.port())); // todo
                                                                                                 // String.format()
    Authentication authentication =
        new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
    classUnderTest.authenticate(authentication);
  }

  @Test
  void authenticate() throws VCertException {
    assertThat(classUnderTest.user()).describedAs("user details").isNotNull();

    assertThat(classUnderTest.user().apiKey()).describedAs("api key details").isNotNull();
    assertThat(classUnderTest.user().apiKey().apiKeyStatus()).describedAs("api key details")
        .isEqualTo("ACTIVE");
    assertThat(classUnderTest.user().apiKey().apiTypes()).containsExactly("foo");
    assertThat(classUnderTest.user().apiKey().apiVersion()).isEqualTo("ALL");
    assertThat(classUnderTest.user().apiKey().username()).isEqualTo("john.doe@example.com");
    assertThat(classUnderTest.user().apiKey().creationDate())
        .isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
    assertThat(classUnderTest.user().apiKey().validityStartDate())
        .isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
    assertThat(classUnderTest.user().apiKey().validityEndDate())
        .isEqualTo(OffsetDateTime.parse("2019-12-31T14:39:51.920Z"));

    assertThat(classUnderTest.user().company()).isNotNull();
    assertThat(classUnderTest.user().company().id())
        .isEqualTo("12345678-1234-1234-1234-12345678901c");
    assertThat(classUnderTest.user().company().name()).isEqualTo("example.com");
    assertThat(classUnderTest.user().company().companyType()).isEqualTo("TPP_CUSTOMER");
    assertThat(classUnderTest.user().company().active()).isTrue();
    assertThat(classUnderTest.user().company().creationDate())
        .isEqualTo(OffsetDateTime.parse("2019-01-01T14:32:50.612Z"));
    assertThat(classUnderTest.user().company().domains()).containsExactly("example.com");

    assertThat(classUnderTest.user().user()).isNotNull();
    assertThat(classUnderTest.user().user().username()).isEqualTo("john.doe@example.com");
    assertThat(classUnderTest.user().user().id()).isEqualTo("12345678-1234-1234-1234-12345678901u");
    assertThat(classUnderTest.user().user().companyId())
        .isEqualTo("12345678-1234-1234-1234-12345678901c");
    assertThat(classUnderTest.user().user().emailAddress()).isEqualTo("john.doe@example.com");
    assertThat(classUnderTest.user().user().userType()).isEqualTo("EXTERNAL");
    assertThat(classUnderTest.user().user().userAccountType()).isEqualTo("WEB_UI");
    assertThat(classUnderTest.user().user().userStatus()).isEqualTo("ACTIVE");
    assertThat(classUnderTest.user().user().creationDate())
        .isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
  }

  @Test // todo: unit test for mapping code to check whatever is null here is mapped correctly.
  void readZoneConfiguration() throws VCertException {

    ZoneConfiguration zoneConfiguration =
        classUnderTest.readZoneConfiguration("My Project\\My Zone");

    assertThat(zoneConfiguration).isNotNull();
    assertThat(zoneConfiguration.organization().equals("Venafi Inc."));
    assertThat(zoneConfiguration.organizationalUnit()).containsExactly("Integrations");
    assertThat(zoneConfiguration.country().equals("US"));
    assertThat(zoneConfiguration.province().equals("Utah"));
    assertThat(zoneConfiguration.locality().equals("Salt Lake"));
    assertThat(zoneConfiguration.policy()).isNotNull();
    assertThat(zoneConfiguration.policy().subjectCNRegexes()).containsExactly("^.*.example.com$",
        "^.*.example.org$", "^.*.example.net$", "^.*.invalid$", "^.*.local$", "^.*.localhost$",
        "^.*.test$");
    assertThat(zoneConfiguration.policy().subjectORegexes()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().subjectOURegexes()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().subjectSTRegexes()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().subjectLRegexes()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().subjectCRegexes()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).isNotNull();
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).isNotNull();
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).hasSize(1);
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keyType())
        .isEqualTo(KeyType.RSA);
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keySizes())
        .containsExactly(2048, 4096);
    assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keyCurves()).isNull();
    assertThat(zoneConfiguration.policy().dnsSanRegExs()).containsExactly("^.*$");
    assertThat(zoneConfiguration.policy().ipSanRegExs()).isNull();
    assertThat(zoneConfiguration.policy().emailSanRegExs()).isNull();
    assertThat(zoneConfiguration.policy().uriSanRegExs()).isNull();
    assertThat(zoneConfiguration.policy().upnSanRegExs()).isNull();
    assertThat(zoneConfiguration.policy().allowWildcards()).isFalse();
    assertThat(zoneConfiguration.policy().allowKeyReuse()).isFalse();
    assertThat(zoneConfiguration.hashAlgorithm())
        .isEqualTo(SignatureAlgorithm.UnknownSignatureAlgorithm);
    assertThat(zoneConfiguration.customAttributeValues()).isNotNull();
    assertThat(zoneConfiguration.customAttributeValues()).isEmpty();
  }


  @Test
  void requestCertificate() throws VCertException {
    CertificateRequest certificateRequest = new CertificateRequest()
        // Signing request borrowed from tpp/connector-test.go#checkCertificateCSRRSA, response
        // unrelated from tpp/connector_test.go#successRequestCertificate
        .csr(
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIBrDCCARUCAQAwbDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxEjAQBgNV\nBAcMCVNhbHQgTGFrZTEPMA0GA1UECgwGVmVuYWZpMQ8wDQYDVQQLDAZEZXZPcHMx\nGDAWBgNVBAMMD3Rlc3QudmVuZGV2LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\ngYkCgYEAqIPiGtjnxep5gQHIiDXhHpHYhr/ndwFKQ2HNGftD3AMjMDyolSQY27w7\nPScTZXcuENew0zsH4iA7UsFhEGB6AIoelBWxiWc1SYRNslIgsSxsRlksJowFcL/E\n40qkmL0TerI2vq829jF3XY6X1E3e1OXo0kbmBLwEB/xnpfuvpt0CAwEAAaAAMA0G\nCSqGSIb3DQEBCwUAA4GBAGsKm5fJ8Zm/j9XMPXhPYmOdiDj+9QlcFq7uRRqwpxo7\nC507RR5Pj2zBRZRLJcc/bNTQFqnW92kIcvJ+YvrQl/GkEMKM2wds/RyMXRHtOJvZ\nYQt6JtkAeQOMECJ7RRHrZiG+m2by2YAB2krthK2gJGSr80xWzZWzrgdwdTe2sxUG\n-----BEGIN CERTIFICATE REQUEST-----"
                .getBytes());
    // todo: improve test: add request matcher (and add data to request to ensure it gets passed
    // through all right)
    ZoneConfiguration zoneConfiguration = new ZoneConfiguration();
    zoneConfiguration.zoneId("Default");
    String requestId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
    assertThat(requestId).isEqualTo("04c051d0-f118-11e5-8b33-d96cf8021ce5");
  }
  
  @Test
  void generateRequest() throws VCertException, IOException {
    ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration("My Project\\My Zone");
    String commonName = TestUtils.randomCN();
    CertificateRequest certificateRequest =
        new CertificateRequest().subject(new CertificateRequest.PKIXName().commonName(commonName))
            .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()));
    CertificateRequest request = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
    assertThat(certificateRequest.csr()).isNotEmpty();

    try (PEMParser pemParser = new PEMParser(new StringReader(Strings.fromByteArray(request.csr())))) {
      PKCS10CertificationRequest pkcs10Request = (PKCS10CertificationRequest) pemParser.readObject();
      String subject = pkcs10Request.getSubject().toString();
      assertThat(subject).contains(String.format("CN=%s", commonName));
      assertThat(subject).contains("O=Venafi Inc.");
      assertThat(subject).contains("OU=Integrations");
      assertThat(subject).contains("C=US");
      assertThat(subject).contains("L=Salt Lake");
      assertThat(subject).contains("ST=Utah");
      assertThat(certificateRequest.privateKey()).isInstanceOf(RSAPrivateKey.class);
      assertThat(((RSAPrivateKey) certificateRequest.privateKey()).getModulus().bitLength()).isEqualTo(4096);
    }
  }
}
