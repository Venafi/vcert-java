package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZoneConfigurationTest {

    @Test
    @DisplayName("Validate a policy match")
    void validateCertificateRequest() throws VCertException {
        final ZoneConfiguration zoneConfiguration = getBaseZoneConfiguration();

        zoneConfiguration.validateCertificateRequest(getDefaultCertificateRequest());
    }

    @Test
    @DisplayName("Expect CN not to match with a termination")
    void invalidCNMatch() throws VCertException {
        final ZoneConfiguration zoneConfiguration = getBaseZoneConfiguration();
        final CertificateRequest certificateRequest = getDefaultCertificateRequest();
        certificateRequest.subject().commonName("vcert.text.vfidev.com.example");

        final Throwable exception = assertThrows(VCertException.class,
                () -> zoneConfiguration.validateCertificateRequest(certificateRequest));

        assertThat(exception.getMessage()).contains("CN does not match any of the allowed CN");
    }

    @Test
    @DisplayName("Invalid match in the state province")
    void invalidProvince() throws VCertException {
        final ZoneConfiguration zoneConfiguration = getBaseZoneConfiguration();
        final CertificateRequest certificateRequest = getDefaultCertificateRequest();
        certificateRequest.subject().province(Arrays.asList("Test"));

        final Throwable exception = assertThrows(VCertException.class,
                () -> zoneConfiguration.validateCertificateRequest(certificateRequest));

        assertThat(exception.getMessage()).contains("does not match any of the allowed State/Province");
    }


    @Test
    @DisplayName("Key Policies should fail if do not match")
    void invalidKeyPolices() throws VCertException {
        final ZoneConfiguration zoneConfiguration = getBaseZoneConfiguration();
        final CertificateRequest certificateRequest = getDefaultCertificateRequest();
        certificateRequest.keyType(KeyType.ECDSA);

        final Throwable exception = assertThrows(VCertException.class,
                () -> zoneConfiguration.validateCertificateRequest(certificateRequest));

        assertThat(exception.getMessage()).contains("Key Type and Size do not match");
    }

    private CertificateRequest getDefaultCertificateRequest() {
        final ZoneConfiguration zoneConfiguration = getBaseZoneConfiguration();
        final CertificateRequest request = new CertificateRequest();
        final CertificateRequest.PKIXName subject = new CertificateRequest.PKIXName();
        subject.commonName("vcert.text.vfidev.com");
        subject.organization(singletonList("Venafi, Inc."));
        subject.organizationalUnit(Arrays.asList("Engineering"));
        subject.locality(singletonList("Las Vegas"));
        subject.province(singletonList("Nevada"));
        subject.country(singletonList("US"));

        request.subject(subject);
        request.dnsNames(emptyList());
        return  request;
    }

    private ZoneConfiguration getBaseZoneConfiguration() {
        final ZoneConfiguration defaultZoneConf = new ZoneConfiguration();
        final Policy policy = new Policy();
        final AllowedKeyConfiguration allowedKeyConfiguration = new AllowedKeyConfiguration();

        defaultZoneConf.organization("Venafi");
        defaultZoneConf.organizationalUnit(Arrays.asList("Engineering", "Automated Test"));
        defaultZoneConf.country("US");
        defaultZoneConf.province("Utah");
        defaultZoneConf.locality("SLC");

        allowedKeyConfiguration.keyType(KeyType.RSA);
        allowedKeyConfiguration.keySizes(singletonList(4096));

        policy.allowedKeyConfigurations(Arrays.asList(allowedKeyConfiguration));
        policy.subjectCNRegexes(singletonList(".*vfidev.com"));
        policy.subjectORegexes(singletonList("Venafi, Inc."));
        policy.subjectOURegexes(singletonList("Engineering"));
        policy.subjectSTRegexes(singletonList("Nevada"));
        policy.subjectLRegexes(singletonList("Las Vegas"));
        policy.subjectCRegexes(singletonList("US"));
        policy.dnsSanRegExs(singletonList(".*"));

        defaultZoneConf.policy(policy);
        return defaultZoneConf;
    }

}