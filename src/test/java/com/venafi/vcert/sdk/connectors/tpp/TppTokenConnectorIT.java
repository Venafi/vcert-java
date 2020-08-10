package com.venafi.vcert.sdk.connectors.tpp;

import com.github.jenspiegsa.wiremockextension.InjectServer;
import com.github.jenspiegsa.wiremockextension.WireMockExtension;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static com.venafi.vcert.sdk.SignatureAlgorithm.SHA256WithRSA;
import static com.venafi.vcert.sdk.certificate.EllipticCurve.*;
import static com.venafi.vcert.sdk.certificate.EllipticCurve.EllipticCurveP521;
import static com.venafi.vcert.sdk.certificate.KeyType.ECDSA;
import static com.venafi.vcert.sdk.certificate.KeyType.RSA;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(WireMockExtension.class)
public class TppTokenConnectorIT {

    @InjectServer
    private WireMockServer serverMock;
    private TppTokenConnector classUnderTest;
    private TokenInfo info;

    @BeforeEach
    void setup() throws VCertException {
        classUnderTest = new TppTokenConnector(Tpp.connect("http://localhost:" + serverMock.port() + "/"));
        // String.format()
        Authentication auth = Authentication.builder()
                .user("user")
                .password("pass")
                .build();
        info = classUnderTest.getAccessToken(auth);
    }

    @Test
    @DisplayName("should start and inject server.")
    void shouldInjectServer() {
        assertThat(serverMock).isNotNull();
        assertThat(serverMock.isRunning()).describedAs("server expected to be running.").isTrue();
    }

    @Test
    void authenticate() throws VCertException {
        // call in @BeforeEach
        assertThat(info.accessToken()).isEqualTo("12345678-1234-1234-1234-123456789012");
        assertThat(info.refreshToken()).isEqualTo("abcdefgh-abcd-abcd-abcd-abcdefghijkl");
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration("tag");

        assertThat(zoneConfiguration).isNotNull();
        assertThat(zoneConfiguration.organization()).isNull();
        assertThat(zoneConfiguration.organizationalUnit()).isNotNull();
        assertThat(zoneConfiguration.organizationalUnit()).isEmpty();
        assertThat(zoneConfiguration.country()).isNull();
        assertThat(zoneConfiguration.province()).isNull();
        assertThat(zoneConfiguration.locality()).isNull();
        assertThat(zoneConfiguration.policy()).isNotNull();
        assertThat(zoneConfiguration.policy().subjectCNRegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().subjectORegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().subjectOURegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().subjectSTRegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().subjectLRegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().subjectCRegexes()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).isNotNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations()).hasSize(2);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keyType())
                .isEqualTo(RSA);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keySizes())
                .containsExactly(512, 1024, 2048, 4096, 8192);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(0).keyCurves()).isNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(1).keyType())
                .isEqualTo(ECDSA);
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(1).keySizes()).isNull();
        assertThat(zoneConfiguration.policy().allowedKeyConfigurations().get(1).keyCurves())
                .containsExactly(EllipticCurveP224, EllipticCurveP256, EllipticCurveP384,
                        EllipticCurveP521);
        assertThat(zoneConfiguration.policy().dnsSanRegExs()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().ipSanRegExs()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().emailSanRegExs()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().uriSanRegExs()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().upnSanRegExs()).containsExactly(".*");
        assertThat(zoneConfiguration.policy().allowWildcards()).isTrue();
        assertThat(zoneConfiguration.policy().allowKeyReuse()).isFalse();
        assertThat(zoneConfiguration.hashAlgorithm()).isEqualTo(SHA256WithRSA);
        assertThat(zoneConfiguration.customAttributeValues()).isNotNull();
        assertThat(zoneConfiguration.customAttributeValues()).isEmpty();
    }
}
