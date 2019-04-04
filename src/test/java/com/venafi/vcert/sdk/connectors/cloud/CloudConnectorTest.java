package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.connectors.cloud.domain.Company;
import com.venafi.vcert.sdk.connectors.cloud.domain.User;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CloudConnectorTest {

    @Mock
    private Cloud cloud;
    private CloudConnector classUnderTest;

    @Captor
    private ArgumentCaptor<UserAccount> userAccountArgumentCaptor;

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
    @DisplayName("Register a new user on venafi cloud")
    void register() throws  VCertException{
        final String email = "me@venafi.com";
        final Authentication auth =
                new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        final UserDetails userDetails = mock(UserDetails.class);

        when(cloud.register(eq("12345678-1234-1234-1234-123456789012"), userAccountArgumentCaptor.capture()))
                .thenReturn(userDetails);

        classUnderTest.authenticate(auth);
        classUnderTest.register(email);

        UserAccount userAccount = userAccountArgumentCaptor.getValue();
        assertEquals(userAccount.username(), email);
        assertEquals(userAccount.userAccountType(), "API");
        assertEquals(classUnderTest.user(), userDetails);
    }

    @Test
    void requestCertificate() throws VCertException {
        Security.addProvider(new BouncyCastleProvider());

        String apiKey = "12345678-1234-1234-1234-123456789012";
        Zone zone = new Zone().defaultCertificateIdentityPolicy("defaultCertificateIdentityPolicy").defaultCertificateUsePolicy("defaultCertificateUsePolicy");
        when(cloud.zoneByTag(eq("Default"), eq(apiKey))).thenReturn(zone);
        when(cloud.policyById(eq("defaultCertificateIdentityPolicy"), eq(apiKey))).thenReturn(new CertificatePolicy().certificatePolicyType("CERTIFICATE_IDENTITY"));
        // TODO: To add checks for policies see com.venafi.vcert.sdk.connectors.cloud.CloudConnector.getPoliciesById and adapt test
        when(cloud.policyById(eq("defaultCertificateUsePolicy"), eq(apiKey))).thenReturn(new CertificatePolicy().certificatePolicyType("CERTIFICATE_USE"));
        when(cloud.certificateRequest(eq(apiKey), any(CloudConnector.CertificateRequestsPayload.class))) // todo: check request payload values
            .thenReturn(new CloudConnector.CertificateRequestsResponse()
                    .certificateRequests(Collections.singletonList(new CloudConnector.CertificateRequestsResponseData()
                            .id("jackpot"))));

        CertificateRequest request = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName()
                        .commonName("random name")
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Collections.singletonList("Automated Tests")));

        final Authentication auth =
                new Authentication(null, null, apiKey);
        classUnderTest.authenticate(auth);

        ZoneConfiguration zoneConfig = classUnderTest.readZoneConfiguration("Default");
        classUnderTest.generateRequest(zoneConfig, request);

        String actual = classUnderTest.requestCertificate(request, "Default");

        assertThat(actual).isEqualTo("jackpot");
    }

}