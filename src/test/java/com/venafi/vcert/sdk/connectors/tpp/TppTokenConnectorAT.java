package com.venafi.vcert.sdk.connectors.tpp;

import static com.venafi.vcert.sdk.TestUtils.getTestIps;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CustomField;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

import feign.FeignException;

class TppTokenConnectorAT {

    private static TppTokenConnector classUnderTest = new TppTokenConnector(Tpp.connect(System.getenv("TPP_TOKEN_URL")));
    private static TokenInfo info;

    @BeforeEach
    void authenticate() throws VCertException {
        Security.addProvider(new BouncyCastleProvider());
        //Executes only once to ensure the same token is used across the tests
        if(TppTokenConnectorAT.info == null){
            Authentication authentication = Authentication.builder()
                    .user(System.getenv("TPPUSER"))
                    .password(System.getenv("TPPPASSWORD"))
                    .scope("certificate:manage,revoke,discover;configuration:manage")
                    .build();

            TokenInfo info = classUnderTest.getAccessToken(authentication);

            assertThat(info).isNotNull();
            assertThat(info.authorized()).isTrue();
            assertThat(info.errorMessage()).isNull();
            assertThat(info.accessToken()).isNotNull();
            assertThat(info.refreshToken()).isNotNull();

            TppTokenConnectorAT.info = info;
        }
    }

    @Test
    @DisplayName("Authenticate with credentials from Config object")
    void authenticateNoParameter() throws VCertException{
        TokenInfo localInfo = classUnderTest.getAccessToken();

        assertThat(localInfo).isNotNull();
        assertThat(localInfo.authorized()).isTrue();
        assertThat(localInfo.errorMessage()).isNull();
        assertThat(localInfo.accessToken()).isNotNull();
        assertThat(localInfo.refreshToken()).isNotNull();
    }

    @Test
    @DisplayName("Authenticate with invalid credentials")
    void authenticateInvalid() throws VCertException{
        Authentication authentication = Authentication.builder()
            .user("sample")
            .password("password")
            .scope("certificate:manage,revoke,discover")
            .build();

        classUnderTest.credentials(authentication);

        TokenInfo info = classUnderTest.getAccessToken();
        assertThat(info).isNotNull();
        assertThat(info.authorized()).isFalse();
        assertThat(info.errorMessage()).isNotNull();


        // After setting invalid credentials to TPP, setting variable <info> to null
        // will allow for new token to be authorized
        TppTokenConnectorAT.info = null;
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            classUnderTest.readZoneConfiguration(System.getenv("TPPZONE"));
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }

    @Test
    void ping() throws VCertException {
        assertThatCode(() -> classUnderTest.ping()).doesNotThrowAnyException();
    }

    @Test
    void generateRequest() throws VCertException, IOException {
        String zone = System.getenv("TPPZONE");
        String commonName = TestUtils.randomCN();
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zone);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
                        .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);

        assertThat(certificateRequest.csr()).isNotEmpty();

        PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(
                new StringReader(new String(certificateRequest.csr()))).readObject();

        // Values overridden by policy which is why they don't match the above values
        String subject = request.getSubject().toString();

        assertThat(subject).contains(format("CN=%s", commonName));
    }

    @Test
    void requestCertificate() throws VCertException, SocketException, UnknownHostException {
        String zoneName = System.getenv("TPPZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        CertificateRequest csrRequestOnly = new CertificateRequest().csr(certificateRequest.csr());
        assertThat(classUnderTest.requestCertificate(csrRequestOnly, zoneConfiguration)).isNotNull();
    }

    @Test
    void retrieveCertificate() throws VCertException, SocketException, UnknownHostException {
        String zoneName = System.getenv("TPPZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);

        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.privateKey()).isNotNull();
    }

    @Test
    void revokeCertificate() throws VCertException, SocketException, UnknownHostException {
        String zoneName = System.getenv("TPPZONE");
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();

        // just wait for the certificate issuance
        classUnderTest.retrieveCertificate(certificateRequest);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.reason("key-compromise");
        revocationRequest.certificateDN(certificateRequest.pickupId());

        classUnderTest.revokeCertificate(revocationRequest);
    }

    @Test
    void renewCertificate() throws VCertException, UnknownHostException, SocketException,
            CertificateException, NoSuchAlgorithmException {
        String zoneName = System.getenv("TPPZONE");
        String commonName = TestUtils.randomCN();
        ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(zoneName);
        CertificateRequest certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

        certificateRequest = classUnderTest.generateRequest(zoneConfiguration, certificateRequest);
        String certificateId = classUnderTest.requestCertificate(certificateRequest, zoneConfiguration);
        assertThat(certificateId).isNotNull();

        PEMCollection pemCollection = classUnderTest.retrieveCertificate(certificateRequest);
        X509Certificate cert = (X509Certificate) pemCollection.certificate();

        String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();

        CertificateRequest certificateRequestToRenew = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName().commonName(commonName)
                        .organization(Collections.singletonList("Venafi"))
                        .organizationalUnit(Collections.singletonList("Demo"))
                        .country(Collections.singletonList("GB"))
                        .locality(Collections.singletonList("Bracknell"))
                        .province(Collections.singletonList("Berkshire")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
                .ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);
        classUnderTest.generateRequest(zoneConfiguration, certificateRequestToRenew);

        String renewRequestId = classUnderTest.renewCertificate(
                new RenewalRequest().request(certificateRequestToRenew).thumbprint(thumbprint));

        assertThat(renewRequestId).isNotNull();
    }

    @Test
    void importCertificate() throws VCertException {
        final String cert = "-----BEGIN CERTIFICATE-----\n"
                + "MIIDdjCCAl6gAwIBAgIRAPqSZQ04IjWgO2rwIDRcOY8wDQYJKoZIhvcNAQENBQAw\n"
                + "gYAxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYDVQQHDA5TYWx0IExh\n"
                + "a2UgQ2l0eTEPMA0GA1UECgwGVmVuYWZpMRswGQYDVQQLDBJOT1QgRk9SIFBST0RV\n"
                + "Q1RJT04xGzAZBgNVBAMMElZDZXJ0IFRlc3QgTW9kZSBDQTAeFw0xODA5MTIxMzUw\n"
                + "MzNaFw0xODEyMTExMzUwMzNaMCQxIjAgBgNVBAMTGWltcG9ydC52ZW5hZmkuZXhh\n"
                + "bXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChjQk0jSE5\n"
                + "ktVdH8bAM0QCpGs1rOOVMmRkMc7d4hQ6bTlFlIypMq9t+1O2Z8i4fiKDS7vSBmBo\n"
                + "WBgN9e0fbAnKEvBIcNLBS4lmwzRDxDCrNV3Dr5s+yJtUw9V2XBwiXbtW7qs5+c0O\n"
                + "y7a2S/5HudXUlAuXf7SF4MboMMpHRg+UkyA4j0peir8PtmlJjlYBt3lZdaeLlD6F\n"
                + "EIlIVQFZ6ulUF/kULhxhTUl2yNUUzJ/bqJlhFU6pkL+GoW1lnaZ8FYXwA1EKYyRk\n"
                + "DYL581eqvIBJY9tCNWbOdU1r+5wR4OOKe/WWWhcDC6nL/M8ZYhfQg1nHoD58A8Dk\n"
                + "H4AAt8A3EZpdAgMBAAGjRjBEMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB\n"
                + "/wQCMAAwHwYDVR0jBBgwFoAUzqRFDvLX0mz4AjPb45tLGavm8AcwDQYJKoZIhvcN\n"
                + "AQENBQADggEBABa4wqh+A63O5PHrdUCBSmQs9ve/oIXj561VBmqXkTHLrtKtbtcA\n"
                + "yvsMi8RD8BibBAsUCljkCmLoQD/XeQFtsPlMAxisSMYhChh58008CIYDR8Nf/qoe\n"
                + "YfzdMB/3VWCqTn9KGF8aMKeQvbFvuqmbtdCv//eYe6mNe2fa/x6PSdGMi4BPmjUC\n"
                + "PmBT4p1iwMtu8LnL4UM4awjmmExR4X4rafcyGEbf0D/CRfhDLSwxvrrVcWd6TMMY\n"
                + "HPZ/pw//+UrVLgEEsyM2zwf+LokbszPBvPAtHMJtr7Pnq2MQtEEkLfPqOWG3ol1H\n"
                + "t+4v2LIW1q4GkwOUjPqgyIaJC5jj5pH9/g8=\n" + "-----END CERTIFICATE-----";

        final String pk = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIEpAIBAAKCAQEAoY0JNI0hOZLVXR/GwDNEAqRrNazjlTJkZDHO3eIUOm05RZSM\n"
                + "qTKvbftTtmfIuH4ig0u70gZgaFgYDfXtH2wJyhLwSHDSwUuJZsM0Q8QwqzVdw6+b\n"
                + "PsibVMPVdlwcIl27Vu6rOfnNDsu2tkv+R7nV1JQLl3+0heDG6DDKR0YPlJMgOI9K\n"
                + "Xoq/D7ZpSY5WAbd5WXWni5Q+hRCJSFUBWerpVBf5FC4cYU1JdsjVFMyf26iZYRVO\n"
                + "qZC/hqFtZZ2mfBWF8ANRCmMkZA2C+fNXqryASWPbQjVmznVNa/ucEeDjinv1lloX\n"
                + "Awupy/zPGWIX0INZx6A+fAPA5B+AALfANxGaXQIDAQABAoIBAE7of6WOhbsEcHkz\n"
                + "CzZYFBEiVEd8chEu8wBJn9ybD/xV21KUM3x1iGC1EPeYi98ppRvygwQcHzz4Qo+X\n"
                + "HsJpWAK+62TGzvqhNbTfBglPq+IEiA8MGE07WTu3B+3vIcLbe6UDoNkJndJrSIyU\n"
                + "Y9iO+dYClgLi2r9FwoIpSrQzkWqlB3edle4Nq1WABtWTOSDYysz1gk0KrLmQQfXP\n"
                + "CPiwkL0SjB+sfbOiVX0B2liV2oxJ5VZWNo/250wFcvrcYrgTNtEVNMXtpN0tnRMH\n"
                + "NPwnY+B9WGu/NVhtvOcOTPHq9xQhbmBCS1axikizCaIqEOyegdeDJ4ASJnVybfCA\n"
                + "KzjoCpUCgYEAwOmeEvzSP8hCKtLPU8QDBA1y+mEvZMwBY4qr3hfqv3qa0QmFvxkk\n"
                + "7Ubmy2oFOoUnVgnhRzAf/bajbkz4ScUgd2JrUdIEhNNVwDn/llnS/UHBlZY++BtW\n"
                + "mvyon9ObXgPNPoHcJqzrqARu8PPJQEsZ+xjxM/gyif3prn6Uct6R8B8CgYEA1mHd\n"
                + "Astwht39z16FoX9rQRGgx64Z0nesfTjl+4mkypz6ukkcfU1GjobqEG3k666+OJk1\n"
                + "SRs8s20Pahrh21LO5x/QtvChhZ+nIedqlhBlNH9uUJI9ChbUN0luetiSPT8F5aqg\n"
                + "gZMY13K5icAQ+98EcNwl7ZhVPq0BvLlbqTWi9gMCgYEAjtVqoQxob6lKtIJZ19+t\n"
                + "i/aZRyFmAe+6p4UpM8vpl9SjhFrUmGV5neV9ROc+79FfCqlOD3NmfGgaIbUDsTsv\n"
                + "irVoWLBzgBUpzKYkw6HGQpXJS4RvIyy6tw6Tm6MFylpuQPXNlyU5ZrHBos4eGGiC\n"
                + "2BPjo2MFqH5D41r9dv+sdmkCgYEAtSJYx3y2pe04/xYhGFP9fivzyeMrRC4DWoZR\n"
                + "oxcoWl0KZ41QefppzBDoAVuo2Q17AX1JjWxq/DsAlCkEffhYguXZxkhIYQuE/lt2\n"
                + "LjbKG/IzdfYphrXFNrVfmIIWBZOTWvqwxOpRSfBQHbhfYUCMkwMfNMHJ/LvWxOtk\n"
                + "K/L6rpsCgYB6p9RU2kXexAh9kUpbGqVeJBoIh6ArXHgepESE/7dPw26D0DM0mef0\n"
                + "X1MasxN3JF7ZsSGfcCLXnICSJHuNTy9WztqF3hUbQwYd9vmZxtzAo5/fK4DVAaXS\n"
                + "ZtIVl/CH/az0xqLKWIlmWOip9SfUVlZdgege+PlQtRqoFVOsH8+MEg==\n"
                + "-----END RSA PRIVATE KEY-----";

        String zone = System.getenv("TPPZONE");
        ImportRequest importRequest = new ImportRequest();
        importRequest.certificateData(cert);
        importRequest.privateKeyData(pk);
        importRequest.policyDN(classUnderTest.getPolicyDN(zone));


        ImportResponse response = classUnderTest.importCertificate(importRequest);
        assertThat(response).isNotNull();
        assertThat(response.certificateDN()).isNotNull();
        assertThat(response.certificateVaultId()).isNotNull();
        assertThat(response.privateKeyVaultId()).isNotNull();

    }

    @Test
    void readPolicyConfiguration() {
        assertThrows(UnsupportedOperationException.class,
                () -> classUnderTest.readPolicyConfiguration("zone"));
    }

    @Test
    void refreshToken() throws VCertException{
        TokenInfo refreshInfo = classUnderTest.refreshAccessToken(TestUtils.CLIENT_ID);

        assertThat(refreshInfo).isNotNull();
        assertThat(refreshInfo.authorized()).isTrue();
        assertThat(refreshInfo.errorMessage()).isNull();
        assertThat(refreshInfo.accessToken()).isNotNull();
        assertThat(refreshInfo.accessToken()).isNotEqualTo(info.accessToken());
        assertThat(refreshInfo.refreshToken()).isNotNull();
        assertThat(refreshInfo.refreshToken()).isNotEqualTo(info.refreshToken());
    }

    @Test
    void refreshTokenInvalid() throws VCertException{
        Authentication invalidCredentials = Authentication.builder()
            .accessToken("abcde==")
            .refreshToken("1234-1234-12345-123")
            .build();
        classUnderTest.credentials(invalidCredentials);

        TokenInfo info = classUnderTest.refreshAccessToken(TestUtils.CLIENT_ID);

        assertThat(info).isNotNull();
        assertThat(info.authorized()).isFalse();
        assertThat(info.errorMessage()).isNotNull();

        // After setting invalid credentials to TPP, setting variable <info> to null
        // will allow for new token to be authorized
        TppTokenConnectorAT.info = null;
    }

    @Test
    void revokeToken() throws VCertException{
        int status = classUnderTest.revokeAccessToken();
        assertThat(status).isEqualTo(200);

        // After revoking the current token, setting variable <info> to null
        // will allow for new token to be authorized
        TppTokenConnectorAT.info = null;
    }

    @Test
    void revokeTokenInvalid() throws VCertException{
        Authentication invalidCredentials = Authentication.builder()
            .accessToken("abcde==")
            .refreshToken("1234-1234-12345-123")
            .build();
        classUnderTest.credentials(invalidCredentials);

        assertThrows(VCertException.class, () ->classUnderTest.revokeAccessToken());

        // After setting invalid credentials to TPP, setting variable <info> to null
        // will allow for new token to be authorized
        TppTokenConnectorAT.info = null;
    }
    
    @Test
    @DisplayName("Create a cerfiticate that contais custom fileds and validate if certifiate were created correctly")
    void createCertificateValidateValidityHours() throws UnknownHostException, VCertException {

  	  String token = TestUtils.getAccessToken();
  	  String commonName = TestUtils.randomCN();

  	  assertTrue(token != "");

  	  String url = System.getenv(TestUtils.TPP_TOKEN_URL);
  	  String zone = System.getenv(TestUtils.TPP_ZONE);


  	  final Authentication auth = Authentication.builder()
  			  .accessToken(token)
  			  .build();

  	  final Config config = Config.builder()
  			  .connectorType(ConnectorType.TPP_TOKEN)
  			  .baseUrl(url)
  			  .credentials(auth)
  			  .build();

  	  final VCertTknClient client =  new VCertTknClient(config);
  	  
  	  //Custom fields
  	  List<CustomField> customFields = new ArrayList<CustomField>();
  	  customFields.add(new CustomField("custom", "java-test"));
  	  customFields.add(new CustomField("cfList", "item2"));
  	  customFields.add(new CustomField("cfListMulti", "tier1"));
  	  customFields.add(new CustomField("cfListMulti", "tier2"));


  	  CertificateRequest cr = new CertificateRequest()
  			  .subject(new CertificateRequest.PKIXName().commonName(commonName)
  					  .organization(Collections.singletonList("Venafi, Inc."))
  					  .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
  					  .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
  					  .province(Collections.singletonList("Utah")))
  			  .dnsNames(Arrays.asList("alfa.venafi.example", "bravo.venafi.example", "charlie.venafi.example"))
  			  .ipAddresses(Arrays.asList(InetAddress.getByName("10.20.30.40"),InetAddress.getByName("172.16.172.16")))
  			  .keyType(KeyType.RSA)
  			  .customFields(customFields);

  	  ZoneConfiguration zoneConfiguration = client.readZoneConfiguration(zone);
  	  cr = client.generateRequest(zoneConfiguration, cr);

  	  // Submit the certificate request
  	  client.requestCertificate(cr, zoneConfiguration);

  	  // Retrieve PEM collection from Venafi
  	  PEMCollection pemCollection = client.retrieveCertificate(cr);


  	  //At this moment certificate, must be created, it will fail if some custom fields aren't supported or specified on tpp
  	  //so is enough to validate if certificate is created.
  	  assertTrue(pemCollection.certificate() != null);

    }

    @Test
    @DisplayName("TPP - Testing the setPolicy() and getPolicy() methods")
    public void createAndGetPolicy() throws VCertException {

        String policyName = TppTestUtils.getRandomZone();

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

        classUnderTest.setPolicy(policyName, policySpecification);

        PolicySpecification policySpecificationReturned = classUnderTest.getPolicy(policyName);

        //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
        //due it doesn't contain it
        policySpecification.name(policySpecificationReturned.name());
        //setting to null, because the returned should not contains the defaults
        policySpecification.defaults(null);

        assertEquals(policySpecification, policySpecificationReturned);
    }
}
