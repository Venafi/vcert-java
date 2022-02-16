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

import com.venafi.vcert.sdk.policy.converter.cloud.CloudPolicySpecificationValidator;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.policy.domain.PolicySpecificationConst;
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
import com.venafi.vcert.sdk.connectors.cloud.domain.EdgeEncryptionKey;
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

        when(cloud.applicationByName(eq("test_app"), eq(apiKey))).thenReturn(application);

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
        PEMCollection pemCollection = PEMCollection.fromStringPEMCollection(body, ChainOption.ChainOptionIgnore, null, null);

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

        List<String> list = new ArrayList<String>();
        list.add("jackpot");
        CertificateStatus status = new CertificateStatus().status("ISSUED")
                .certificateIds(list);
        
        CertificateDetails certificateDetails = new CertificateDetails().dekHash("12345");
        EdgeEncryptionKey edgeEncryptionKey = new EdgeEncryptionKey();
        
        cloud.certificateDetails(eq("jackpot"), eq(apiKey));

        when(cloud.certificateStatus(eq("jackpot"), eq(apiKey)))
                .thenReturn(status);
        when(cloud.retrieveCertificate(eq("jackpot"), eq(apiKey), eq("ROOT_FIRST")))
                .thenReturn(Response.builder()
                        .request(Request.create(Request.HttpMethod.GET, "http://localhost",
                                new HashMap<String, Collection<String>>(), null, null))
                        .status(200)
                        .body(body, Charset.forName("UTF-8"))
                        .build());
        when(cloud.certificateDetails(eq("jackpot"), eq(apiKey))).thenReturn(certificateDetails);
        when(cloud.retrieveEdgeEncryptionKey(eq("12345"), eq(apiKey))).thenReturn(edgeEncryptionKey);

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

        List<String> list = new ArrayList<String>();
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

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of MaxValidDays")
    public void testExceptionValidatingMaxValidDays() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the maxValidDays to null to validate that the related VCertException is thrown
        policySpecification.policy().maxValidDays(-10);

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(CloudTestUtils.getVCertExceptionMessage( CloudPolicySpecificationValidator.MAX_VALID_DAYS_EXCEPTION_MESSAGE), exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of CertificateAuthority")
    public void testExceptionValidatingCertificateAuthority() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the certificate authority to null to validate that the related VCertException is thrown
        policySpecification.policy().certificateAuthority("certificateAuthority");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(CloudTestUtils.getVCertExceptionMessage( CloudPolicySpecificationValidator.CERTIFICATE_AUTHORITY_EXCEPTION_MESSAGE), exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy Orgs with wildcard value")
    public void testExceptionValidatingPolicyOrgsWhenWildcards() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the orgs to a list of values which contains ".*" to validate that the related VCertException is thrown
        policySpecification.policy().subject().orgs(new String[]{PolicySpecificationConst.ALLOW_ALL, "org1"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy OrgUnits with wildcard value")
    public void testExceptionValidatingPolicyOrgUnitsWhenWildcards() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the orgUnits to a list of values which contains ".*" to validate that the related VCertException is thrown
        policySpecification.policy().subject().orgUnits(new String[]{PolicySpecificationConst.ALLOW_ALL, "org1"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy Localities with wildcard value")
    public void testExceptionValidatingPolicyLocalitiesWhenWildcards() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Localities to a list of values which contains ".*" to validate that the related VCertException is thrown
        policySpecification.policy().subject().localities(new String[]{PolicySpecificationConst.ALLOW_ALL, "Merida"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy States with wildcard value")
    public void testExceptionValidatingPolicyStatesWhenWildcards() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the States to a list of values which contains ".*" to validate that the related VCertException is thrown
        policySpecification.policy().subject().states(new String[]{PolicySpecificationConst.ALLOW_ALL, "Yucatan"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy Countries with wildcard value")
    public void testExceptionValidatingPolicyCountriesWhenWildcards() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Countries to a list of values which contains ".*" to validate that the related VCertException is thrown
        policySpecification.policy().subject().countries(new String[]{PolicySpecificationConst.ALLOW_ALL, "Mexico"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy Countries with not 2 char values")
    public void testExceptionValidatingPolicyCountriesWithNot2Characters() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Countries to a list of values which contains a string with more than
        //2 chars to validate that the related VCertException is thrown
        policySpecification.policy().subject().countries(new String[]{"US", "Mexico"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy KeyType")
    public void testExceptionValidatingPolicyKeyTypeContainsInvalidValue() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the keypair to a list of values which contains not only "RSA" to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().keyTypes(new String[]{"RSA", "ECDSA"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy KeySizes")
    public void testExceptionValidatingPolicyKeySizes() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the keysizes to a list of values which contains a no valid value to validate that the related VCertException is thrown
        policySpecification.policy().keyPair().rsaKeySizes(new Integer[]{1024,3072});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy SAN IpAllowed")
    public void testExceptionValidatingSANIpAllowed() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the ipAllowed to true to validate that the related VCertException is thrown
        policySpecification.policy().subjectAltNames().ipAllowed(true);

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy SAN EmailAllowed")
    public void testExceptionValidatingSANEmailAllowed() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the emailAllowed to true to validate that the related VCertException is thrown
        policySpecification.policy().subjectAltNames().emailAllowed(true);

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Policy SAN UriAllowed")
    public void testExceptionValidatingSANUriAllowed() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the uriAllowed to true to validate that the related VCertException is thrown
        policySpecification.policy().subjectAltNames().uriAllowed(true);

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults Org not matching with the Policy Orgs values")
    public void testExceptionValidatingDefaultOrg() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Default Org to a value which doesn't match with the values in the Policy Orgs values
        //to validate that the related VCertException is thrown
        policySpecification.defaults().subject().org("Ven");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults OrgUnits not matching with the Policy OrgUnits values")
    public void testExceptionValidatingDefaultOrgUnits() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Default OrgUnits to a value which doesn't match with the values in the Policy
        //OrgUnits values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().orgUnits(new String[]{"Dev"});

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults Locality not matching with the Policy Localities values")
    public void testExceptionValidatingDefaultLocality() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Default Locality to a value which doesn't match with the values in the
        //Policy Localities values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().locality("Mer");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults State not matching with the Policy States values")
    public void testExceptionValidatingDefaultState() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Default State to a value which doesn't match with the values in the Policy State values
        //to validate that the related VCertException is thrown
        policySpecification.defaults().subject().state("Yuc");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults Country not matching with the Policy Countries values")
    public void testExceptionValidatingDefaultCountry() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Default country to a value which doesn't match with the values in the
        //Policy Countries values to validate that the related VCertException is thrown
        policySpecification.defaults().subject().country("CO");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY
                        , PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Defaults Country with not 2 char values")
    public void testExceptionValidatingDefaultCountryWithNot2Characters() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the Country to a value which contains a string with more than 2 chars
        //to validate that the related VCertException is thrown
        policySpecification.policy(null);
        policySpecification.defaults().subject().country("MEX");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Default KeyType")
    public void testExceptionValidatingDefaultKeyTypeDoesntMatchWithPolicyKeyType() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the keypair to a value which doesn't match with "RSA"
        //to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().keyType("ECDSA");

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Default KeySize with a not supported value")
    public void testExceptionValidatingDefaultKeySize() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the default keysize to a value which is not supported to
        //validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().rsaKeySize( 3072 );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE)
                , exception.getMessage());
    }

    @Test
    @DisplayName("Cloud - Testing Exception in Validation of Default KeySize with a value not matching with the Policy KeySizes")
    public void testExceptionValidatingDefaultKeySizeDoesntMatchWithPolicyKeySizes() throws VCertException {

        classUnderTest.authenticate(new Authentication(null, null, "12345678-1234-1234-1234-123456789012"));

        PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();

        //setting the default keysize to a value which is not matching with
        //the Policy KeySizes to validate that the related VCertException is thrown
        policySpecification.defaults().keyPair().rsaKeySize( 4096 );

        Exception exception = assertThrows(VCertException.class, () -> classUnderTest.setPolicy( CloudTestUtils.getRandomZone(), policySpecification ));
        assertEquals(
                CloudTestUtils.getVCertExceptionMessage(
                        CloudPolicySpecificationValidator.DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE
                        , PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE
                        , PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)
                , exception.getMessage());
    }
}
