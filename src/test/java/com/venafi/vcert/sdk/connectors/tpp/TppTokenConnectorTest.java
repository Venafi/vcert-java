package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.LockableValue;
import com.venafi.vcert.sdk.connectors.LockableValues;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import feign.Request;
import feign.Response;
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

import java.security.Security;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class TppTokenConnectorTest {

    private static final Logger logger = LoggerFactory.getLogger(TppConnectorTest.class);
    private static final String ACCESS_TOKEN = "12345678-1234-1234-1234-123456789012";
    private static final String HEADER_AUTHORIZATION = "Bearer " + ACCESS_TOKEN;
    private static final String REFRESH_TOKEN = "abcdefgh-abcd-abcd-abcd-abcdefghijkl";

    @Mock
    private Tpp tpp;
    private TppTokenConnector classUnderTest;
    private TokenInfo info;

    @Captor
    private ArgumentCaptor<TppTokenConnector.CertificateRenewalRequest> certificateRenewalRequestArgumentCaptor;

    @BeforeEach
    void setUp() throws VCertException {
        this.classUnderTest = new TppTokenConnector(tpp);

        AuthorizeTokenResponse response =
                new AuthorizeTokenResponse().accessToken(ACCESS_TOKEN).
                        refreshToken(REFRESH_TOKEN);
        when(tpp.authorizeToken(any(TppTokenConnector.AuthorizeTokenRequest.class))).thenReturn(response);

        Authentication authentication = Authentication.builder().user("user").password("pass").build();
        info = classUnderTest.getAccessToken(authentication);
    }

    @Test
    void canGetAuthToken() throws VCertException {
        assertNotNull(info.accessToken());
        assertNotNull(info.refreshToken());
    }

    @Test
    @DisplayName("Request a certificate from TPP")
    void requestCertificate() throws VCertException {
        Security.addProvider(new BouncyCastleProvider());

        TppTokenConnector.ReadZoneConfigurationRequest expectedRZCRequest =
                new TppTokenConnector.ReadZoneConfigurationRequest("\\VED\\Policy\\\\VED\\Policy\\myZone");
        when(
                tpp.readZoneConfigurationToken(eq(expectedRZCRequest), eq(HEADER_AUTHORIZATION)))
                .thenReturn(
                        new TppTokenConnector.ReadZoneConfigurationResponse()
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
        when(tpp.requestCertificateToken(any(TppTokenConnector.CertificateRequestsPayload.class), eq(HEADER_AUTHORIZATION)))
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
        when(tpp.searchCertificatesToken(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);

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
        when(tpp.searchCertificatesToken(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);
        when(certificateSearchResponse.certificates())
                .thenReturn(Arrays.asList(new Tpp.Certificate(), new Tpp.Certificate()));

        final Throwable throwable =
                assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
        assertThat(throwable.getMessage()).contains("More than one certificate was found");
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
        when(tpp.searchCertificatesToken(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);
        when(certificateSearchResponse.certificates()).thenReturn(Arrays.asList(certificate));
        when(certificate.certificateRequestId()).thenReturn("test_certificate_requestid");
        when(tpp.renewCertificateToken(certificateRenewalRequestArgumentCaptor.capture(), any()))
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
        when(tpp.renewCertificateToken(certificateRenewalRequestArgumentCaptor.capture(), any()))
                .thenReturn(certificateRenewalResponse);
        when(certificateRenewalResponse.success()).thenReturn(true);

        String result = classUnderTest.renewCertificate(renewalRequest);
        assertThat(result).isEqualTo("certificateDN");
    }

    @Test
    @DisplayName("Refresh access token")
    void refreshAccessToken() throws VCertException{
        final RefreshTokenResponse tokenResponse = mock(RefreshTokenResponse.class);

        when(tokenResponse.accessToken()).thenReturn("123456");
        when(tokenResponse.refreshToken()).thenReturn("abcdef");

        when(tpp.refreshToken(any(AbstractTppConnector.RefreshTokenRequest.class))).thenReturn(tokenResponse);

        TokenInfo newInfo = classUnderTest.refreshAccessToken("vcert-sdk");
        assertNotNull(newInfo);
        assertNotNull(newInfo.accessToken());
        assertNotNull(newInfo.refreshToken());

        assertThat(newInfo.accessToken()).isNotEqualTo(info.accessToken());
        assertThat(newInfo.refreshToken()).isNotEqualTo(info.refreshToken());
    }

    @Test
    @DisplayName("Refresh invalid access token")
    void refreshAccessTokenInvalid(){
        final Request request = Request.create(Request.HttpMethod.POST, "", new HashMap<String, Collection<String>>(), null);

        when(tpp.refreshToken(any(AbstractTppConnector.RefreshTokenRequest.class))).thenThrow(new FeignException.BadRequest("400 Grant has been revoked, has expired, or the refresh token is invalid", request, null));

        final Throwable throwable =
                assertThrows(VCertException.class, () -> classUnderTest.refreshAccessToken("vcert-sdk"));
        logger.info("VCertException = %s", throwable.getMessage());

        assertThat(throwable.getMessage()).contains("Grant has been revoked, has expired, or the refresh token is invalid");
    }

    @Test
    @DisplayName("Revoke access token")
    void revokeAccessToken() throws VCertException{
        final Request request = Request.create(Request.HttpMethod.GET, "", new HashMap<String, Collection<String>>(), null);

        final Response response = Response.builder().status(200).request(request).build();

        when(tpp.revokeToken(eq(HEADER_AUTHORIZATION))).thenReturn(response);

        int responseValue = classUnderTest.revokeAccessToken();

        assertThat(responseValue).isEqualTo(200);
    }

    @Test
    @DisplayName("Revoke access token invalid")
    void revokeAccessTokenInvalid(){
        final Request request = Request.create(Request.HttpMethod.GET, "", new HashMap<String, Collection<String>>(), null);

        final Response response = Response.builder().status(202).request(request).build();

        when(tpp.revokeToken(eq(HEADER_AUTHORIZATION))).thenReturn(response);

        Throwable throwable = assertThrows(VCertException.class, () ->classUnderTest.revokeAccessToken());
        assertThat(throwable.getMessage()).contains("202");
    }
}