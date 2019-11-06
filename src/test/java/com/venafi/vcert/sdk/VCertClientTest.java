package com.venafi.vcert.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import feign.FeignException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

class VCertClientTest {

  private final Connector connector = mock(Connector.class);
  private final VCertClient classUnderTest = new VCertClient(connector);

  @Test
  @DisplayName("Create venafi cloud client")
  void getTypeCloud() throws VCertException {
    final Config config = Config.builder().connectorType(ConnectorType.CLOUD).build();

    VCertClient client = new VCertClient(config);

    assertThat(client).isNotNull();
    assertThat(client.getType()).isEqualTo(ConnectorType.CLOUD);
    assertThat(Security.getProviders()).anyMatch(p -> p instanceof BouncyCastleProvider);
  }

  @Test
  @DisplayName("Create venafi tpp client")
  void getTypeTpp() throws VCertException {
    final Config config = Config.builder().connectorType(ConnectorType.TPP)
        .baseUrl("https://localhost/vesdk/").build();

    VCertClient client = new VCertClient(config);

    assertThat(client).isNotNull();
    assertThat(client.getType()).isEqualTo(ConnectorType.TPP);
    assertThat(Security.getProviders()).anyMatch(p -> p instanceof BouncyCastleProvider);
  }

  @Test
  @DisplayName("Set baseurl")
  void setBaseUrl() throws VCertException {
    classUnderTest.setBaseUrl("https://base_url_test/");
    verify(connector).setBaseUrl("https://base_url_test/");
  }

  @Test
  @DisplayName("Set venafi default zone")
  void setZone() {
    classUnderTest.setZone("test_zone");
    verify(connector).setZone("test_zone");
  }

  @Test
  @DisplayName("Ping venafi service")
  void ping() throws VCertException {
    classUnderTest.ping();
    verify(connector).ping();
  }

  @Test
  @DisplayName("Ping venafi service with server error")
  void pingWithException() throws VCertException {
    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector).ping();

    assertThrows(VCertException.class, () -> classUnderTest.ping());
  }

  @Test
  @DisplayName("Authenticated with venafi endpoint")
  void authenticateWithException() throws VCertException {
    final Authentication auth = mock(Authentication.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .authenticate(auth);

    assertThrows(VCertException.class, () -> classUnderTest.authenticate(auth));
  }

  @Test
  @DisplayName("Authenticated with venafi endpoint with server error")
  void authenticate() throws VCertException {
    final Authentication auth = mock(Authentication.class);
    classUnderTest.authenticate(auth);

    verify(connector).authenticate(auth);
  }

  @Test
  @DisplayName("Read zone configuration")
  void readZoneConfiguration() throws VCertException {
    classUnderTest.readZoneConfiguration("test_zone");

    verify(connector).readZoneConfiguration("test_zone");
  }

  @Test
  @DisplayName("Read zone configuration with server error")
  void readZoneConfigurationWithServerError() throws VCertException {
    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .readZoneConfiguration("test_zone");

    assertThrows(VCertException.class, () -> classUnderTest.readZoneConfiguration("test_zone"));
  }

  @Test
  @DisplayName("Generate request")
  void generateRequest() throws VCertException {
    final ZoneConfiguration zoneConfiguration = mock(ZoneConfiguration.class);
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);

    classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
    verify(connector).generateRequest(zoneConfiguration, certificateRequest);
  }

  @Test
  @DisplayName("Generate request with server error")
  void generateRequestWithServerError() throws VCertException {
    final ZoneConfiguration zoneConfiguration = mock(ZoneConfiguration.class);
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .generateRequest(zoneConfiguration, certificateRequest);

    assertThrows(VCertException.class,
        () -> classUnderTest.generateRequest(zoneConfiguration, certificateRequest));
  }

  @Test
  @DisplayName("Request certificate")
  void requestCertificate() throws VCertException {
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);
    classUnderTest.requestCertificate(certificateRequest, "test_zone");

    verify(connector).requestCertificate(certificateRequest, "test_zone");
  }

  @Test
  @DisplayName("Request certificate with server error")
  void requestCertificateWithServerError() throws VCertException {
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .requestCertificate(certificateRequest, "test_zone");

    assertThrows(VCertException.class,
        () -> classUnderTest.requestCertificate(certificateRequest, "test_zone"));
  }

  @Test
  @DisplayName("Retrieve certificate")
  void retrieveCertificate() throws VCertException {
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);

    classUnderTest.retrieveCertificate(certificateRequest);
    verify(connector).retrieveCertificate(certificateRequest);

  }

  @Test
  @DisplayName("Retrieve certificate with server error")
  void retrieveCertificateWithServerError() throws VCertException {
    final CertificateRequest certificateRequest = mock(CertificateRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .retrieveCertificate(certificateRequest);

    assertThrows(VCertException.class,
        () -> classUnderTest.retrieveCertificate(certificateRequest));
  }

  @Test
  @DisplayName("Revoke certificate")
  void revokeCertificate() throws VCertException {
    final RevocationRequest revocationRequest = mock(RevocationRequest.class);

    classUnderTest.revokeCertificate(revocationRequest);
    verify(connector).revokeCertificate(revocationRequest);
  }

  @Test
  @DisplayName("Revoke certificate with server error")
  void revokeCertificateWithServerError() throws VCertException {
    final RevocationRequest revocationRequest = mock(RevocationRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .revokeCertificate(revocationRequest);

    assertThrows(VCertException.class, () -> classUnderTest.revokeCertificate(revocationRequest));
  }


  @Test
  @DisplayName("Renew certificate")
  void renewCertificate() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);

    classUnderTest.renewCertificate(renewalRequest);
    verify(connector).renewCertificate(renewalRequest);
  }

  @Test
  @DisplayName("Renew certificate with server error")
  void renewCertificateWithServerError() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .renewCertificate(renewalRequest);

    assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
  }

  @Test
  @DisplayName("Import certificate")
  void importCertificate() throws VCertException {
    final ImportRequest importRequest = mock(ImportRequest.class);

    classUnderTest.importCertificate(importRequest);
    verify(connector).importCertificate(importRequest);
  }

  @Test
  @DisplayName("Import certificate with server error")
  void importCertificateWithServerError() throws VCertException {
    final ImportRequest importRequest = mock(ImportRequest.class);

    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .importCertificate(importRequest);

    assertThrows(VCertException.class, () -> classUnderTest.importCertificate(importRequest));
  }

  @Test
  @DisplayName("Read policy configuration")
  void readPolicyConfiguration() throws VCertException {
    classUnderTest.readZoneConfiguration("test_zone");
    verify(connector).readZoneConfiguration("test_zone");
  }

  @Test
  @DisplayName("Read policy configuration with server error")
  void readPolicyConfigurationWithServerError() throws VCertException {
    doThrow(new FeignException.InternalServerError("Error", "".getBytes())).when(connector)
        .readPolicyConfiguration("test_zone");

    assertThrows(VCertException.class, () -> classUnderTest.readPolicyConfiguration("test_zone"));
  }
}
