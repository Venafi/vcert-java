package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.ConnectorException.CertificateDNOrThumbprintWasNotProvidedException;
import com.venafi.vcert.sdk.connectors.ConnectorException.CertificateNotFoundByThumbprintException;
import com.venafi.vcert.sdk.connectors.ConnectorException.FailedToRevokeTokenException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MoreThanOneCertificateWithSameThumbprintException;
import com.venafi.vcert.sdk.connectors.LockableValue;
import com.venafi.vcert.sdk.connectors.LockableValues;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.policy.converter.tpp.TPPPolicySpecificationValidator;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.policy.domain.PolicySpecificationConst;
import feign.FeignException;
import feign.FeignException.BadRequest;
import feign.Request;
import feign.Response;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class TppTokenConnectorTest {

    private static final Logger logger = LoggerFactory.getLogger(TppTokenConnectorTest.class);
    private static final String ACCESS_TOKEN = "12345678-1234-1234-1234-123456789012";
    private static final String HEADER_AUTHORIZATION = "Bearer " + ACCESS_TOKEN;
    private static final String REFRESH_TOKEN = "abcdefgh-abcd-abcd-abcd-abcdefghijkl";

    @Mock
    private TppToken tpp;
    private TppTokenConnector classUnderTest;
    private TokenInfo info;

    @Captor
    private ArgumentCaptor<TppTokenConnector.CertificateRenewalRequest> certificateRenewalRequestArgumentCaptor;

    @BeforeEach
    void setUp() throws VCertException {
        this.classUnderTest = new TppTokenConnector(tpp);
        
        AuthorizeTokenResponse response = new AuthorizeTokenResponse();
        
        response.accessToken(ACCESS_TOKEN).refreshToken(REFRESH_TOKEN);
        
        when(tpp.authorizeToken(any(TppTokenConnector.AuthorizeTokenRequest.class))).thenReturn(response);

        Authentication authentication = Authentication.builder().user("user").password("pass").build();
        info = classUnderTest.getAccessToken(authentication);
        assertThat(info).isNotNull();
        assertThat(info.authorized()).isTrue();
        assertThat(info.errorMessage()).isNull();
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
                new TppTokenConnector.ReadZoneConfigurationRequest("\\VED\\Policy\\myZone");
        when(
                tpp.readZoneConfiguration(eq(expectedRZCRequest), eq(HEADER_AUTHORIZATION)))
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
        when(tpp.requestCertificate(any(TppTokenConnector.CertificateRequestsPayload.class), eq(HEADER_AUTHORIZATION)))
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

        assertThat(throwable instanceof CertificateDNOrThumbprintWasNotProvidedException);
    }

    @Test
    @DisplayName("Renew Certificate with fingerprint not found")
    void renewCertificateWithFingeprintNoSearchResults() throws VCertException {
        final RenewalRequest renewalRequest = mock(RenewalRequest.class);
        final Tpp.CertificateSearchResponse certificateSearchResponse =
                mock(Tpp.CertificateSearchResponse.class);

        when(renewalRequest.thumbprint()).thenReturn("1111:1111:1111:1111");
        when(tpp.searchCertificates(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);

        final Throwable throwable =
                assertThrows(VCertException.class, () -> classUnderTest.renewCertificate(renewalRequest));
        assertThat(throwable instanceof CertificateNotFoundByThumbprintException);
    }

    @Test
    @DisplayName("Renew Certificate multiple certificates for the fingerprint")
    void renewCertificateWithFingerPrintMultipleCertificates() throws VCertException {
        final RenewalRequest renewalRequest = mock(RenewalRequest.class);
        final Tpp.CertificateSearchResponse certificateSearchResponse =
                mock(Tpp.CertificateSearchResponse.class);

        when(renewalRequest.thumbprint()).thenReturn("1111:1111:1111:1111");
        when(tpp.searchCertificates(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);
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
        when(tpp.searchCertificates(any(), eq(HEADER_AUTHORIZATION))).thenReturn(certificateSearchResponse);
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

    @Test
    @DisplayName("Refresh access token")
    void refreshAccessToken() throws VCertException{
        final RefreshTokenResponse tokenResponse = mock(RefreshTokenResponse.class);

        when(tokenResponse.accessToken()).thenReturn("123456");
        when(tokenResponse.refreshToken()).thenReturn("abcdef");

        when(tpp.refreshToken(any(AbstractTppConnector.RefreshTokenRequest.class))).thenReturn(tokenResponse);

        TokenInfo newInfo = classUnderTest.refreshAccessToken(TestUtils.CLIENT_ID);
        assertNotNull(newInfo);
        assertThat(newInfo.authorized()).isTrue();
        assertThat(newInfo.errorMessage()).isNull();
        assertNotNull(newInfo.accessToken());
        assertNotNull(newInfo.refreshToken());

        assertThat(newInfo.accessToken()).isNotEqualTo(info.accessToken());
        assertThat(newInfo.refreshToken()).isNotEqualTo(info.refreshToken());
    }

    @Test
    @DisplayName("Refresh invalid access token")
    void refreshAccessTokenInvalid() throws VCertException{
        final Request request = Request.create(Request.HttpMethod.POST, "", new HashMap<String, Collection<String>>(), null);

        when(tpp.refreshToken(any(AbstractTppConnector.RefreshTokenRequest.class))).thenThrow(new FeignException.BadRequest("400 Grant has been revoked, has expired, or the refresh token is invalid", request, new byte[]{}) );

        /*TokenInfo info = classUnderTest.refreshAccessToken(TestUtils.CLIENT_ID);
        assertThat(info).isNotNull();
        assertThat(info.authorized()).isFalse();
        assertThat(info.errorMessage()).isNotNull();

        logger.info("VCertException = %s", info.errorMessage());

        assertThat(info.errorMessage()).contains("Grant has been revoked, has expired, or the refresh token is invalid");
        */
        assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> classUnderTest.refreshAccessToken(TestUtils.CLIENT_ID))
	    .withRootCauseInstanceOf(BadRequest.class);
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
        assertThat(throwable instanceof FailedToRevokeTokenException);
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy Orgs with more than one value")
    public void testExceptionValidatingPolicyOrgs() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the orgs to a list of more than 1 values
        //to validate that the related VCertException is thrown
        policySpecification.policy().subject().orgs(new String[]{"Org1", "Org2"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy Localities with more than one value")
    public void testExceptionValidatingPolicyLocalities() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the localities to a list of more than 1 values
        //to validate that the related VCertException is thrown
        policySpecification.policy().subject().localities(new String[]{"Loc1", "Loc2"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy States with more than one value")
    public void testExceptionValidatingPolicyStates() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the states to a list of more than 1 values
        //to validate that the related VCertException is thrown
        policySpecification.policy().subject().states(new String[]{"State1", "State2"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy Countries with more than one value")
    public void testExceptionValidatingPolicyCountries() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the countries to a list of more than 1 values
        //to validate that the related VCertException is thrown
        policySpecification.policy().subject().countries(new String[]{"Country1", "Country2"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy Countries with not 2 char values")
    public void testExceptionValidatingPolicyWithNot2Characters() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Countries to a list of values which contains a string with more than
        //2 chars to validate that the related VCertException is thrown
        policySpecification.policy().subject().countries(new String[]{"USA"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy KeyType that has more than one value")
    public void testExceptionValidatingPolicyKeyTypeHasMoreThanOneValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the keypair to a list of values which contains not only one
        //to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().keyTypes(new String[]{"RSA", "ECDSA"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy KeyType that has unsupported value")
    public void testExceptionValidatingPolicyKeyTypeContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the keypair to a value which is not supported
        //to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().keyTypes(new String[]{"KT"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy KeySizes that has more than one value")
    public void testExceptionValidatingPolicyKeySizesHasMoreThanOneValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the keysizes to a list of values which contains
        //more than on value to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().rsaKeySizes(new Integer[]{1024,3072});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy KeySizes that has unsupported value")
    public void testExceptionValidatingPolicyKeySizesContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the keysizes to a list of values which contains
        //more than on value to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().rsaKeySizes(new Integer[]{256});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy EC that has more than one value")
    public void testExceptionValidatingPolicyECHasMoreThanOneValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the EC to a list of values which contains
        //more than on value to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().ellipticCurves(new String[]{"P256","P384"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Policy EC that has unsupported value")
    public void testExceptionValidatingPolicyECContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the EC to a list of values which contains
        //more than on value to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().ellipticCurves(new String[]{"P224"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults Org not matching with the Policy Orgs values")
    public void testExceptionValidatingDefaultOrg() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Default Org to a value which doesn't match with the values in the
        //Policy Orgs values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().org("Ven");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults OrgUnits not matching with the Policy OrgUnits values")
    public void testExceptionValidatingDefaultOrgUnits() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Default OrgUnits to a value which doesn't match with the values in the Policy
        //OrgUnits values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().orgUnits(new String[]{"Dev"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults Locality not matching with the Policy Localities values")
    public void testExceptionValidatingDefaultLocality() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Default Locality to a value which doesn't match with the values in the
        //Policy Localities values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().locality("Mer");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults State not matching with the Policy States values")
    public void testExceptionValidatingDefaultState() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Default State to a value which doesn't match with the values in the Policy State values
        //to validate that the related VCertException is thrown
        policySpecification.defaults().subject().state("Yuc");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults Country not matching with the Policy Countries values")
    public void testExceptionValidatingDefaultCountry() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Default country to a value which doesn't match with the values in the
        //Policy Countries values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().country("CO");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Defaults Country with not 2 char values")
    public void testExceptionValidatingDefaultCountryWithNot2Characters() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the Country to a value which contains a string with more than 2 chars
        //to validate that the related VCertException is thrown
        policySpecification.policy(null);
        policySpecification.defaults().subject().country("MEX");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default KeyType that has unsupported value")
    public void testExceptionValidatingDefaultKeyTypeContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default keypair to a value which is not supported
        //to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().keyType( "KT" );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default KeyType with a value not matching with the Policy KeyType")
    public void testExceptionValidatingDefaultKeyTypeDoesntMatchWithPolicyKeyType() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default KeyType to a value which is not matching with
        // the Policy KeyType to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().keyType( "ECDSA" );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default KeySize that has unsupported value")
    public void testExceptionValidatingDefaultKeySizeContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default KeySize to a value which is not supported
        //to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().rsaKeySize( 256 );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default KeySize with a value not matching with the Policy KeySize")
    public void testExceptionValidatingDefaultKeySizeDoesntMatchWithPolicyKeyType() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default KeySize to a value which is not matching with
        // the Policy KeySize to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().rsaKeySize( 512 );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default EC that has unsupported value")
    public void testExceptionValidatingDefaultECContainsUnsupportedValue() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default EC to a value which is not supported
        //to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().ellipticCurve( "P224" );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_ELLIPTIC_CURVE)
                , exception.getMessage());
    }

    @Test
    @DisplayName("TPP - Testing Exception in Validation of Default EC with a value not matching with the Policy EC")
    public void testExceptionValidatingDefaultECDoesntMatchWithPolicyEC() throws VCertException {

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        //setting the default KeySize to a value which is not matching with
        // the Policy KeySize to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().ellipticCurves(new String[]{"P256"});
        policySpecification.defaults().keyPair().ellipticCurve( "P384" );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( TppTestUtils.getRandomZone(), policySpecification ));
        Assertions.assertEquals(
                TppTestUtils.getVCertExceptionMessage(
                        TPPPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_ELLIPTIC_CURVE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES)
                , exception.getMessage());
    }

}
