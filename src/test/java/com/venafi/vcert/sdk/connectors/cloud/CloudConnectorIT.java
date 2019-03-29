package com.venafi.vcert.sdk.connectors.cloud;

import com.github.jenspiegsa.wiremockextension.InjectServer;
import com.github.jenspiegsa.wiremockextension.WireMockExtension;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(WireMockExtension.class)
class CloudConnectorIT {

    @InjectServer
    private WireMockServer serverMock;

    private CloudConnector classUnderTest;

    @BeforeEach
    void setup() {
        classUnderTest =  new CloudConnector(Cloud.connect("http://localhost:" + serverMock.port())); // todo String.format()
    }

    @Test
    void authenticate() throws VCertException {
        Authentication authentication = new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        classUnderTest.authenticate(authentication);
        assertThat(classUnderTest.user()).describedAs("user details").isNotNull();

        assertThat(classUnderTest.user().apiKey()).describedAs("api key details").isNotNull();
        assertThat(classUnderTest.user().apiKey().apiKeyStatus()).describedAs("api key details").isEqualTo("ACTIVE");
        assertThat(classUnderTest.user().apiKey().apiTypes()).containsExactly("foo");
        assertThat(classUnderTest.user().apiKey().apiVersion()).isEqualTo("ALL");
        assertThat(classUnderTest.user().apiKey().username()).isEqualTo("john.doe@example.com");
        assertThat(classUnderTest.user().apiKey().creationDate()).isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
        assertThat(classUnderTest.user().apiKey().validityStartDate()).isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
        assertThat(classUnderTest.user().apiKey().validityEndDate()).isEqualTo(OffsetDateTime.parse("2019-12-31T14:39:51.920Z"));

        assertThat(classUnderTest.user().company()).isNotNull();
        assertThat(classUnderTest.user().company().id()).isEqualTo("12345678-1234-1234-1234-12345678901c");
        assertThat(classUnderTest.user().company().name()).isEqualTo("example.com");
        assertThat(classUnderTest.user().company().companyType()).isEqualTo("TPP_CUSTOMER");
        assertThat(classUnderTest.user().company().active()).isTrue();
        assertThat(classUnderTest.user().company().creationDate()).isEqualTo(OffsetDateTime.parse("2019-01-01T14:32:50.612Z"));
        assertThat(classUnderTest.user().company().domains()).containsExactly("example.com");

        assertThat(classUnderTest.user().user()).isNotNull();
        assertThat(classUnderTest.user().user().username()).isEqualTo("john.doe@example.com");
        assertThat(classUnderTest.user().user().id()).isEqualTo("12345678-1234-1234-1234-12345678901u");
        assertThat(classUnderTest.user().user().companyId()).isEqualTo("12345678-1234-1234-1234-12345678901c");
        assertThat(classUnderTest.user().user().emailAddress()).isEqualTo("john.doe@example.com");
        assertThat(classUnderTest.user().user().userType()).isEqualTo("EXTERNAL");
        assertThat(classUnderTest.user().user().userAccountType()).isEqualTo("WEB_UI");
        assertThat(classUnderTest.user().user().userStatus()).isEqualTo("ACTIVE");
        assertThat(classUnderTest.user().user().creationDate()).isEqualTo(OffsetDateTime.parse("2019-01-01T14:39:51.920Z"));
    }

    @Test // todo: unit test for mapping code to check whatever is null here is mapped correctly.
    void readZoneConfiguration() throws VCertException {
        Authentication authentication = new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        classUnderTest.authenticate(authentication);
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration("Default");

        assertThat(zoneConfiguration).isNotNull();
        assertThat(zoneConfiguration.organization()).isNull();
        assertThat(zoneConfiguration.organizationalUnit()).isNull();
        assertThat(zoneConfiguration.country()).isNull();
        assertThat(zoneConfiguration.province()).isNull();
        assertThat(zoneConfiguration.locality()).isNull();
        assertThat(zoneConfiguration.policy()).isNotNull();
        assertThat(zoneConfiguration.policy().subjectCNRegexes()).containsExactly("^.*.example.com$", "^.*.example.org$", "^.*.example.net$", "^.*.invalid$", "^.*.local$", "^.*.localhost$", "^.*.test$");
        assertThat(zoneConfiguration.policy().subjectORegexes()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().subjectOURegexes()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().subjectSTRegexes()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().subjectLRegexes()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().subjectCRegexes()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).isNotNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).isNotNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).hasSize(1);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keytype()).isNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keySizes()).containsExactly(2048);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keyCurves()).isNull();
        assertThat(zoneConfiguration.policy().dnsSanRegExs()).containsExactly("^.*$");
        assertThat(zoneConfiguration.policy().ipSanRegExs()).isNull();
        assertThat(zoneConfiguration.policy().emailSanRegExs()).isNull();
        assertThat(zoneConfiguration.policy().uriSanRegExs()).isNull();
        assertThat(zoneConfiguration.policy().upnSanRegExs()).isNull();
        assertThat(zoneConfiguration.policy().allowWildcards()).isTrue();
        assertThat(zoneConfiguration.policy().allowKeyReuse()).isFalse();
        assertThat(zoneConfiguration.hashAlgorithm()).isNull();
        assertThat(zoneConfiguration.customAttributeValues()).isNotNull();
        assertThat(zoneConfiguration.customAttributeValues()).isEmpty();
    }

    @Test
    void register() throws VCertException {
        Authentication authentication = new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        classUnderTest.authenticate(authentication);
        classUnderTest.register("me@venafi.com");

        assertThat(classUnderTest.user()).isNotNull();
        assertThat(classUnderTest.user().user().username()).isEqualTo("me@venafi.com");
    }
}