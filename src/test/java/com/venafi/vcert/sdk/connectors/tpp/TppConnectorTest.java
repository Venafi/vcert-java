package com.venafi.vcert.sdk.connectors.tpp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.security.Security;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collections;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.LockableValue;
import com.venafi.vcert.sdk.connectors.LockableValues;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.connectors.ConnectorException.MoreThanOneCertificateWithSameThumbprintException;
import com.venafi.vcert.sdk.endpoint.Authentication;

@ExtendWith(MockitoExtension.class)
class TppConnectorTest {

  private static final Logger logger = LoggerFactory.getLogger(TppConnectorTest.class);
  private static final String API_KEY = "12345678-1234-1234-1234-123456789012";

  @Mock
  private Tpp tpp;
  private TppConnector classUnderTest;

  @Captor
  private ArgumentCaptor<TppConnector.CertificateRenewalRequest> certificateRenewalRequestArgumentCaptor;

  @BeforeEach
  void setUp() throws VCertException {
    this.classUnderTest = new TppConnector(tpp);

    AuthorizeResponse response =
        new AuthorizeResponse().apiKey(API_KEY).validUntil(OffsetDateTime.now());
    when(tpp.authorize(any(TppConnector.AuthorizeRequest.class))).thenReturn(response);

    Authentication authentication = new Authentication("user", "pass", null);
    classUnderTest.authenticate(authentication);
  }

  @Test
  void canGetAuthToken() throws VCertException {
    assertNotNull(classUnderTest.apiKey());
  }

  @Test
  @DisplayName("Request a certificate from TPP")
  void requestCertificate() throws VCertException {
    Security.addProvider(new BouncyCastleProvider());

    TppConnector.ReadZoneConfigurationRequest expectedRZCRequest =
        new TppConnector.ReadZoneConfigurationRequest("\\VED\\Policy\\\\VED\\Policy\\myZone");
    when(
        tpp.readZoneConfiguration(eq(expectedRZCRequest), eq(API_KEY)))
            .thenReturn(
                new TppConnector.ReadZoneConfigurationResponse()
                    .policy(
                        new ServerPolicy()
                            .subject(new ServerPolicy.Subject()
                                .organizationalUnit(new LockableValues<String>(false,
                                    Collections.singletonList("OU")))
                                .state(new LockableValue<>(false, "state"))
                                .city(new LockableValue<>(false, "city"))
                                .country(new LockableValue<>(false, "country"))
                                .organization(new LockableValue<>(false, "organization")))


                            .keyPair(new ServerPolicy.KeyPair(new LockableValue<>(false, "keyAlgo"),
                                new LockableValue<>(false, 1024), null))));
    when(tpp.requestCertificate(any(TppConnector.CertificateRequestsPayload.class), eq(API_KEY)))
        .thenReturn(new Tpp.CertificateRequestResponse().certificateDN("reqId"));
    String zoneTag = "myZone";
    ZoneConfiguration zoneConfig =
        classUnderTest.readZoneConfiguration(classUnderTest.getPolicyDN(zoneTag));
    String cn = String.format("t%d-%s.venafi.xample.com", Instant.now().getEpochSecond(),
        RandomStringUtils.randomAlphabetic(4).toLowerCase());
    CertificateRequest request = new CertificateRequest()
        .subject(new CertificateRequest.PKIXName().commonName(cn)
            .organization(Collections.singletonList("Venafi, Inc."))
            .organizationalUnit(Collections.singletonList("Automated Tests"))
            .locality(Collections.singletonList("Las Vegas"))
            .province(Collections.singletonList("Nevada")).country(Collections.singletonList("US")))
        .friendlyName(cn).keyLength(512);
    classUnderTest.generateRequest(zoneConfig, request);
    logger.info("getPolicyDN(ZoneTag) = %s", classUnderTest.getPolicyDN(zoneTag));

    ZoneConfiguration zoneConfiguration = new ZoneConfiguration();
    zoneConfiguration.zoneId(classUnderTest.getPolicyDN(zoneTag));
    String requestId = classUnderTest.requestCertificate(request, zoneConfiguration);
    assertEquals("reqId", requestId);
  }


  @Test
  @DisplayName("Renew Certificate with an empty request")
  void renewCertificateWithEmptyRequest() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);
    final Throwable throwable =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));

    assertThat(throwable.getMessage()).contains("CertificateDN or Thumbprint required");
  }

  @Test
  @DisplayName("Renew Certificate with fingerprint not found")
  void renewCertificateWithFingeprintNoSearchResults() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);
    final Tpp.CertificateSearchResponse certificateSearchResponse =
        mock(Tpp.CertificateSearchResponse.class);

    when(renewalRequest.thumbprint()).thenReturn("1111:1111:1111:1111");
    when(tpp.searchCertificates(any(), eq(API_KEY))).thenReturn(certificateSearchResponse);

    final Throwable throwable =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
    assertThat(throwable.getMessage()).contains("No certificate found using fingerprint");
  }

  @Test
  @DisplayName("Renew Certificate multiple certificates for the fingerprint")
  void renewCertificateWithFingerPrintMultipleCertificates() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);
    final Tpp.CertificateSearchResponse certificateSearchResponse =
        mock(Tpp.CertificateSearchResponse.class);

    when(renewalRequest.thumbprint()).thenReturn("1111:1111:1111:1111");
    when(tpp.searchCertificates(any(), eq(API_KEY))).thenReturn(certificateSearchResponse);
    when(certificateSearchResponse.certificates())
        .thenReturn(Arrays.asList(new Tpp.Certificate(), new Tpp.Certificate()));

    final Throwable throwable =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
    //assertThat(throwable.getMessage()).contains("More than one certificate was found");
    assertThat(throwable instanceof MoreThanOneCertificateWithSameThumbprintException);
  }

  @Test
  @DisplayName("Renew Certificate with fingerprint")
  void renewCertificateWithFingerPrint() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);
    final Tpp.CertificateSearchResponse certificateSearchResponse =
        mock(Tpp.CertificateSearchResponse.class);
    final Tpp.Certificate certificate = mock(Tpp.Certificate.class);
    final Tpp.CertificateRenewalResponse certificateRenewalResponse =
        mock(Tpp.CertificateRenewalResponse.class);

    when(renewalRequest.thumbprint()).thenReturn("1111:1111:1111:1111");
    when(tpp.searchCertificates(any(), eq(API_KEY))).thenReturn(certificateSearchResponse);
    when(certificateSearchResponse.certificates()).thenReturn(Arrays.asList(certificate));
    when(certificate.certificateRequestId()).thenReturn("test_certificate_requestid");
    when(tpp.renewCertificate(certificateRenewalRequestArgumentCaptor.capture(), any()))
        .thenReturn(certificateRenewalResponse);
    when(certificateRenewalResponse.success()).thenReturn(true);

    String result = classUnderTest.renewCertificate(renewalRequest);
    assertThat(result).isEqualTo("test_certificate_requestid");
  }

  @Test
  @DisplayName("Renew Certificate with DN")
  void renewCertificateWithDN() throws VCertException {
    final RenewalRequest renewalRequest = mock(RenewalRequest.class);
    final Tpp.CertificateRenewalResponse certificateRenewalResponse =
        mock(Tpp.CertificateRenewalResponse.class);

    when(renewalRequest.certificateDN()).thenReturn("certificateDN");
    when(tpp.renewCertificate(certificateRenewalRequestArgumentCaptor.capture(), any()))
        .thenReturn(certificateRenewalResponse);
    when(certificateRenewalResponse.success()).thenReturn(true);

    String result = classUnderTest.renewCertificate(renewalRequest);
    assertThat(result).isEqualTo("certificateDN");
  }
}
