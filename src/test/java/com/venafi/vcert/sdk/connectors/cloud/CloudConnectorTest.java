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

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

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
import com.venafi.vcert.sdk.certificate.ChainOption;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.connectors.cloud.domain.Application;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateDetails;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate.AllowedKeyType;
import com.venafi.vcert.sdk.connectors.cloud.domain.Company;
import com.venafi.vcert.sdk.connectors.cloud.domain.User;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.endpoint.Authentication;

import feign.Request;
import feign.Response;

@ExtendWith(MockitoExtension.class)
class CloudConnectorTest {
  private static final String KEY_SECRET = "my secret";

  @Mock
  private Cloud cloud;
  private CloudConnector classUnderTest;

  @Captor
  private ArgumentCaptor<Cloud.SearchRequest> searchRequestArgumentCaptor;

  UserDetails userDetails;


  private String readResourceAsString(String name) throws IOException {
    ClassLoader classLoader = getClass().getClassLoader();
    String path = classLoader.getResource(name).getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    return new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
  }


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

    CertificateIssuingTemplate cit = new CertificateIssuingTemplate();
    cit.id("15c7e3f0-ff0a-11e9-a3f0-2b5db8116980");
    cit.keyTypes(Arrays.asList(new AllowedKeyType("RSA", Arrays.asList(2048))));
    cit.keyReuse(true);
    cit.subjectCNRegexes(Arrays.asList("^random name$", "^.*.example.com$", "^.*.example.org$",
        "^.*.example.net$", "^.*.invalid$", "^.*.local$", "^.*.localhost$", "^.*.test$"));
    cit.subjectORegexes(Arrays.asList("^.*$"));
    cit.subjectOURegexes(Arrays.asList("^.*$"));
    cit.subjectSTRegexes(Arrays.asList());
    cit.subjectLRegexes(Arrays.asList());
    cit.subjectCValues(Arrays.asList());
    cit.sanDnsNameRegexes(Arrays.asList());


    Application application = new Application();
    application.id("d3d7e270-545b-11eb-a494-893c4e1e4fad");
    
    when(cloud.applicationByName(eq("test_app"),eq(apiKey))).thenReturn(application);
    
    when(cloud.certificateIssuingTemplateByAppNameAndCitAlias(eq("test_app"), eq("test_zone"), eq(apiKey))).thenReturn(cit);

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

    ZoneConfiguration zoneConfig = classUnderTest.readZoneConfiguration("test_app\\test_zone");
    classUnderTest.generateRequest(zoneConfig, request);

    String actual = classUnderTest.requestCertificate(request, zoneConfig);

    assertThat(actual).isEqualTo("jackpot");
  }

  @Test
  void retrieveCertificate() throws VCertException, IOException {
    Security.addProvider(new BouncyCastleProvider());

    String apiKey = "12345678-1234-1234-1234-123456789012";
    final Authentication auth = new Authentication(null, null, apiKey);
    classUnderTest.authenticate(auth);

    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);

    CertificateRequest request = new CertificateRequest().subject(
        new CertificateRequest.PKIXName()
        .commonName("random name").organization(singletonList("Venafi, Inc."))
        .organizationalUnit(singletonList("Automated Tests")));
    request
        .pickupId("jackpot")
        .keyType(KeyType.RSA)
        .keyPair(new KeyPair(pemCollection.certificate().getPublicKey(),
            pemCollection.privateKey()))
        .keyPassword(KEY_SECRET);
    
   List<String>  list = new ArrayList<String>();
		   list.add("jackpot");
    CertificateStatus status = new CertificateStatus().status("ISSUED")
    		.certificateIds(list);

    when(cloud.certificateStatus(eq("jackpot"), eq(apiKey)))
        .thenReturn(status);
    when(cloud.certificateViaCSR(eq("jackpot"), eq(apiKey), eq("ROOT_FIRST")))
        .thenReturn(Response.builder()
            .request(Request.create(Request.HttpMethod.GET, "http://localhost",
                new HashMap<String, Collection<String>>(), null, null))
            .status(200)
            .body(body, Charset.forName("UTF-8"))
            .build());

    PEMCollection pemCollection2 = classUnderTest.retrieveCertificate(request);
    assertThat(pemCollection2).isNotNull();
    assertThat(pemCollection2.certificate()).isNotNull();
    assertThat(pemCollection2.privateKey()).isNotNull();
    assertThat(pemCollection2.privateKeyPassword()).isEqualTo(KEY_SECRET);
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
    String requestId = "request_1";

    final String thumbprint = "52030990E3DC44199DA11C2D73E41EF8EAD8A4E1";
    final RenewalRequest renewalRequest = new RenewalRequest();
    
    CertificateRequest request = mock(CertificateRequest.class);
    renewalRequest.request(request);
    
    final Cloud.CertificateSearchResponse searchResponse =
        mock(Cloud.CertificateSearchResponse.class);

    final CertificateStatus certificateStatus = mock(CertificateStatus.class);

    renewalRequest.thumbprint(thumbprint);
    final Cloud.Certificate certificate1 = new Cloud.Certificate();
    certificate1.certificateRequestId(requestId);

    final CloudConnector.CertificateRequestsResponse requestsResponse =
        mock(CloudConnector.CertificateRequestsResponse.class);

    final CloudConnector.CertificateRequestsResponseData requestsResponseData =
        mock(CloudConnector.CertificateRequestsResponseData.class);
    
    
    //CertificateDetails certDetails = cloud.certificateDetails(certificateId, auth.apiKey());
    CertificateDetails certDetails = new CertificateDetails();
    certDetails.id("007");
    certDetails.certificateRequestId(requestId);
    
    List<String>  list = new ArrayList<String>();
	   list.add(requestId);

	 when(cloud.certificateDetails(eq(requestId), eq(apiKey))).thenReturn(certDetails);
	    when(cloud.searchCertificates(eq(apiKey), searchRequestArgumentCaptor.capture()))
        .thenReturn(searchResponse);
    when(searchResponse.certificates()).thenReturn(singletonList(certificate1));
    when(cloud.certificateStatus(requestId, apiKey)).thenReturn(certificateStatus);
    when(certificateStatus.certificateIds()).thenReturn(list);

    when(cloud.certificateRequest(eq(apiKey), any(CloudConnector.CertificateRequestsPayload.class)))
        .thenReturn(requestsResponse);
    when(requestsResponse.certificateRequests()).thenReturn(singletonList(requestsResponseData));
    when(requestsResponseData.id()).thenReturn("certificate_result");
    String fakeCSR = "fake csr";
    byte[] bytes = fakeCSR.getBytes();
    when(renewalRequest.request().csr()).thenReturn(bytes);

    classUnderTest.authenticate(auth);
    assertThat(classUnderTest.renewCertificate(renewalRequest)).isEqualTo("certificate_result");
  }
}
