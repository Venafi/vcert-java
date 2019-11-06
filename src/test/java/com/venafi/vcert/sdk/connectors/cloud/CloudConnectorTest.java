package com.venafi.vcert.sdk.connectors.cloud;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CertificateStatus;
import com.venafi.vcert.sdk.certificate.ManagedCertificate;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.cloud.domain.Company;
import com.venafi.vcert.sdk.connectors.cloud.domain.User;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;

@ExtendWith(MockitoExtension.class)
class CloudConnectorTest {

  @Mock
  private Cloud cloud;
  private CloudConnector classUnderTest;

  @Captor
  private ArgumentCaptor<Cloud.SearchRequest> searchRequestArgumentCaptor;

  UserDetails userDetails;


  @BeforeEach
  void setUp() {
    classUnderTest = new CloudConnector(cloud);
    userDetails = new UserDetails().user(new User()).company(new Company());
    when(cloud.authorize(anyString())).thenReturn(userDetails);
  }

  @Test
  void authenticates() throws VCertException {
    Authentication auth = new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
    classUnderTest.authenticate(auth);
    assertEquals(userDetails, classUnderTest.user());
  }

  @Test
  void requestCertificate() throws VCertException {
    Security.addProvider(new BouncyCastleProvider());

    String apiKey = "12345678-1234-1234-1234-123456789012";
    Zone zone = new Zone().defaultCertificateIdentityPolicy("defaultCertificateIdentityPolicy")
        .defaultCertificateUsePolicy("defaultCertificateUsePolicy");
    when(cloud.zoneByTag(eq("Default"), eq(apiKey))).thenReturn(zone);
    when(cloud.policyById(eq("defaultCertificateIdentityPolicy"), eq(apiKey)))
        .thenReturn(new CertificatePolicy().certificatePolicyType("CERTIFICATE_IDENTITY"));
    // TODO: To add checks for policies see
    // com.venafi.vcert.sdk.connectors.cloud.CloudConnector.getPoliciesById and adapt test
    when(cloud.policyById(eq("defaultCertificateUsePolicy"), eq(apiKey)))
        .thenReturn(new CertificatePolicy().certificatePolicyType("CERTIFICATE_USE"));
    when(cloud.certificateRequest(eq(apiKey), any(CloudConnector.CertificateRequestsPayload.class))) // todo:
                                                                                                     // check
                                                                                                     // request
                                                                                                     // payload
                                                                                                     // values
        .thenReturn(new CloudConnector.CertificateRequestsResponse().certificateRequests(
            singletonList(new CloudConnector.CertificateRequestsResponseData().id("jackpot"))));

    CertificateRequest request = new CertificateRequest().subject(new CertificateRequest.PKIXName()
        .commonName("random name").organization(singletonList("Venafi, Inc."))
        .organizationalUnit(singletonList("Automated Tests")));

    final Authentication auth = new Authentication(null, null, apiKey);
    classUnderTest.authenticate(auth);

    ZoneConfiguration zoneConfig = classUnderTest.readZoneConfiguration("Default");
    classUnderTest.generateRequest(zoneConfig, request);

    String actual = classUnderTest.requestCertificate(request, "Default");

    assertThat(actual).isEqualTo("jackpot");
  }

  @Test
  @DisplayName("Renew a certificate that do not exists in Cloud should fail")
  void renewCertificateNotFound() throws VCertException {
    final String apiKey = "12345678-1234-1234-1234-123456789012";
    final Authentication auth = new Authentication(null, null, apiKey);

    final String thumbprint = "52030990E3DC44199DA11C2D73E41EF8EAD8A4E1";
    final RenewalRequest renewalRequest = new RenewalRequest();
    final Cloud.CertificateSearchResponse searchResponse =
        mock(Cloud.CertificateSearchResponse.class);

    renewalRequest.thumbprint(thumbprint);

    when(cloud.searchCertificates(eq(apiKey), searchRequestArgumentCaptor.capture()))
        .thenReturn(searchResponse);

    classUnderTest.authenticate(auth);
    Throwable exception =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
    assertThat(exception.getMessage()).contains(thumbprint);
  }

  @Test
  @DisplayName("Renew a certificate without request details in cloud should fail")
  void renewCertificateEmptyRequest() throws VCertException {
    final String apiKey = "12345678-1234-1234-1234-123456789012";
    final Authentication auth = new Authentication(null, null, apiKey);

    final RenewalRequest renewalRequest = new RenewalRequest();
    final Cloud.CertificateSearchResponse searchResponse =
        mock(Cloud.CertificateSearchResponse.class);

    classUnderTest.authenticate(auth);
    Throwable exception =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
    assertThat(exception.getMessage()).contains("CertificateDN or Thumbprint required");
  }

  @Test
  @DisplayName("Renew a certificate with same fingerprint for multiple requests ids should fail")
  void renewCertificateMultipleRequestIds() throws VCertException {
    final String apiKey = "12345678-1234-1234-1234-123456789012";
    final Authentication auth = new Authentication(null, null, apiKey);

    final String thumbprint = "52030990E3DC44199DA11C2D73E41EF8EAD8A4E1";
    final RenewalRequest renewalRequest = new RenewalRequest();
    final Cloud.CertificateSearchResponse searchResponse =
        mock(Cloud.CertificateSearchResponse.class);

    renewalRequest.thumbprint(thumbprint);

    when(cloud.searchCertificates(eq(apiKey), searchRequestArgumentCaptor.capture()))
        .thenReturn(searchResponse);

    final Cloud.Certificate certificate1 = new Cloud.Certificate();
    certificate1.certificateRequestId("request_1");

    final Cloud.Certificate certificate2 = new Cloud.Certificate();
    certificate2.certificateRequestId("request_2");

    when(searchResponse.certificates()).thenReturn(Arrays.asList(certificate1, certificate2));

    classUnderTest.authenticate(auth);
    Throwable exception =
        assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));

    assertThat(exception.getMessage()).contains("More than one CertificateRequestId was found");
    assertThat(exception.getMessage()).contains(thumbprint);
  }

  @Test
  @DisplayName("Renew a certificate with fingerprint")
  void renewCertificate() throws VCertException {
    final String apiKey = "12345678-1234-1234-1234-123456789012";
    final Authentication auth = new Authentication(null, null, apiKey);

    final String thumbprint = "52030990E3DC44199DA11C2D73E41EF8EAD8A4E1";
    final RenewalRequest renewalRequest = new RenewalRequest();

    final Cloud.CertificateSearchResponse searchResponse =
        mock(Cloud.CertificateSearchResponse.class);

    final CertificateStatus certificateStatus = mock(CertificateStatus.class);
    final ManagedCertificate managedCertificate = mock(ManagedCertificate.class);
    renewalRequest.thumbprint(thumbprint);
    final Cloud.Certificate certificate1 = new Cloud.Certificate();
    certificate1.certificateRequestId("request_1");

    final CloudConnector.CertificateRequestsResponse requestsResponse =
        mock(CloudConnector.CertificateRequestsResponse.class);

    final CloudConnector.CertificateRequestsResponseData requestsResponseData =
        mock(CloudConnector.CertificateRequestsResponseData.class);

    when(cloud.searchCertificates(eq(apiKey), searchRequestArgumentCaptor.capture()))
        .thenReturn(searchResponse);
    when(searchResponse.certificates()).thenReturn(singletonList(certificate1));
    when(cloud.certificateStatus("request_1", apiKey)).thenReturn(certificateStatus);
    when(certificateStatus.managedCertificateId()).thenReturn("test_managed_certificate_id");
    when(certificateStatus.zoneId()).thenReturn("test_zone_id");
    when(cloud.managedCertificate("test_managed_certificate_id", apiKey))
        .thenReturn(managedCertificate);
    when(managedCertificate.latestCertificateRequestId()).thenReturn("request_1");
    when(cloud.certificateRequest(eq(apiKey), any(CloudConnector.CertificateRequestsPayload.class)))
        .thenReturn(requestsResponse);
    when(requestsResponse.certificateRequests()).thenReturn(singletonList(requestsResponseData));
    when(requestsResponseData.id()).thenReturn("certificate_result");

    classUnderTest.authenticate(auth);
    assertThat(classUnderTest.renewCertificate(renewalRequest)).isEqualTo("certificate_result");
  }
}
