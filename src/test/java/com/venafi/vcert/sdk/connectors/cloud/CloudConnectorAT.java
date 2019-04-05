package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CloudConnectorAT {

    private CloudConnector classUnderTest;

    @BeforeEach
    public void authenticate() throws VCertException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cloud cloud = Cloud.connect(System.getenv("VENAFI_CLOUD_URL"));
        classUnderTest = new CloudConnector(cloud);
        Authentication authentication = new Authentication(null, null, System.getenv("VENAFI_API_KEY"));
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(System.getenv("VENAFI_ZONE"));
        } catch(FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }


    @Test
    @DisplayName("Fetch certificate from a cloud provider should be succesfuly after requested")
    void fetchCertificate() throws VCertException {
        try {
            final CertificateRequest certificateRequest = new CertificateRequest();

            //Todo externalise the certificate CSR or the ceation for AC
            final String csr = "" +
                    "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    "MIICtzCCAZ8CAQAwcjELMAkGA1UEBhMCVUsxFzAVBgNVBAMMDm9wZW5jcmVkby50\n" +
                    "ZXN0MQ8wDQYDVQQHDAZMb25kb24xDzANBgNVBAoMBkxvbmRvbjESMBAGA1UECAwJ\n" +
                    "T3BlbmNyZWRvMRQwEgYDVQQLDAtFbmdpbmVlcmluZzCCASIwDQYJKoZIhvcNAQEB\n" +
                    "BQADggEPADCCAQoCggEBAKsWVhtbxMguBkrGqOb02EWqmBHo6swA/h57jdAq1Vjj\n" +
                    "ACrqFE+3tWu8CHxM/d12vKj2PlKNKXdWtP+2s5Y/vQjNifV+lZPOBoYtOxhcIi8x\n" +
                    "84rKnxlf13j5K8/b6K19LU9b5r7Yzgs6VuIzUTsXqVkm3gMWcdlf2xfvvvb63f8+\n" +
                    "lrzT7fjn+oeGYBfgoOZSNgUXTNyjz6aJF/GzBmEZsVUfn1ML2UyVL7qCqCB8b2J9\n" +
                    "4AvF4iR3Z1Mp0h6ck+I8WhThGcCr6LRdEpocbLVpIH0wiuxIwOkFfYTWzNdp9lwb\n" +
                    "cz4QazcjahDK3n6y9sHl+3+wX/chzXfSQo4NYKpGu0MCAwEAAaAAMA0GCSqGSIb3\n" +
                    "DQEBCwUAA4IBAQB8E6pFXq1cJJpwIXumfbwYGf7BUoZvxjdL9TvNZSb2vGu0yMFr\n" +
                    "XObRn6Bx4fdo6KdnPifSIRq2Sg1J7l38Gvzb5aDRHCMPtGW49cp/2LK/dk+1ZQDf\n" +
                    "aVu3D3D+eoed7poiJ0BlENtb4i9HtuEynHpcNp322O98Lc3np7s/eG7oRkribAE2\n" +
                    "OPVeCyqSXNDdnBWnUsDYlxpvvrs8cKZcxLBJjGhq+YiFMoygCcBF7z6KmiH3bDuT\n" +
                    "G6P0myqqq38BoULQebBzUTw8pcA/6fQqe6FuteQGNtM/b0SU8qmIMYWjyCDbVmIf\n" +
                    "iAfGQ3dVXwbj6CHSSaKoBA160FFSKSs7Yif+\n" +
                    "-----END CERTIFICATE REQUEST-----\n";

            certificateRequest.csr(csr.getBytes());
            final String requestId = classUnderTest.requestCertificate(certificateRequest, System.getenv("VENAFI_ZONE"));

            certificateRequest.pickupId(requestId);
            PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);

            assertThat(pemCollection.certificate()).isNotNull();
            assertThat(pemCollection.chain()).hasSizeBetween(1,3);
            assertThat(pemCollection.privateKey()).isNull();
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }


    }
}