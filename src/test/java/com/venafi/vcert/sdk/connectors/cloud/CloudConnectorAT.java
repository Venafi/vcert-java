package com.venafi.vcert.sdk.connectors.cloud;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;

import feign.FeignException;

class CloudConnectorAT {
	
	@RegisterExtension
	public final CloudConnectorResource connectorResource = new CloudConnectorResource();

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
        	connectorResource.connector().readZoneConfiguration(TestUtils.CLOUD_ZONE);
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }

    @Test
    void generateRequest() throws VCertException, IOException {
        String commonName = TestUtils.randomCN();
        CloudConnector connector = connectorResource.connector();
        ZoneConfiguration zoneConfiguration = connector.readZoneConfiguration(TestUtils.CLOUD_ZONE);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .keyType(KeyType.RSA);
        
        certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
        assertThat(certificateRequest.csr()).isNotEmpty();

        PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(
                new StringReader(Strings.fromByteArray(certificateRequest.csr()))).readObject();

        String subject = request.getSubject().toString();
        assertThat(subject).contains(String.format("CN=%s", commonName));
        assertThat(subject).contains("O=Venafi\\, Inc.");
        assertThat(subject).contains("OU=Engineering");
        assertThat(subject).contains("OU=Automated Tests");
        assertThat(subject).contains("C=US");
        assertThat(subject).contains("L=SLC");
        assertThat(subject).contains("ST=Utah");
    }

    @Test
    void importCertificate() {
        assertThrows(UnsupportedOperationException.class,
                () -> connectorResource.connector().importCertificate(new ImportRequest()));
    }

    @Test
    void readPolicyConfiguration() {
        assertThrows(UnsupportedOperationException.class,
                () -> connectorResource.connector().readPolicyConfiguration("zone"));
    }
}
