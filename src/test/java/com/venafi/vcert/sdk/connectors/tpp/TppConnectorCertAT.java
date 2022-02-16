/**
 * 
 */
package com.venafi.vcert.sdk.connectors.tpp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;
import com.venafi.vcert.sdk.certificate.DataFormat;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.utils.VCertUtils;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class TppConnectorCertAT {
	
	@RegisterExtension
	public static final TppConnectorCertResource connectorResource = new TppConnectorCertResource();

	@Test
	void renewCertificate() throws VCertException, UnknownHostException, SocketException,
	        CertificateException, NoSuchAlgorithmException {
		
		TppConnector connector = connectorResource.connector();
		ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
		CertificateRequest certificateRequest = connector.generateRequest(zoneConfiguration, connectorResource.certificateRequest());
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	    X509Certificate cert = (X509Certificate) pemCollection.certificate();
	
	    String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();
	
	    CertificateRequest certificateRequestToRenew = new CertificateRequest()
	            .subject(certificateRequest.subject())
	            .dnsNames(certificateRequest.dnsNames())
	            .ipAddresses(certificateRequest.ipAddresses())
	            .keyType(certificateRequest.keyType())
	            .keyLength(certificateRequest.keyLength());
	    connector.generateRequest(zoneConfiguration, certificateRequestToRenew);
	
	    String renewRequestId = connector.renewCertificate(
	            new RenewalRequest().request(certificateRequestToRenew).thumbprint(thumbprint));
	
	    assertThat(renewRequestId).isNotNull();
	}

	@Test
	void requestCertificate() throws VCertException, SocketException, UnknownHostException {
	    TppConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest();
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    CertificateRequest csrRequestOnly = new CertificateRequest().csr(certificateRequest.csr());
	    assertThat(connector.requestCertificate(csrRequestOnly, zoneConfiguration)).isNotNull();
	}

	@Test
	void retrieveCertificate() throws VCertException, SocketException, UnknownHostException {
		TppConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest();
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	
	    assertThat(pemCollection.certificate()).isNotNull();
	    assertThat(pemCollection.privateKey()).isNotNull();
	}

	@Test
	void revokeCertificate() throws VCertException, SocketException, UnknownHostException {
		TppConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest();
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	
	    // just wait for the certificate issuance
	    connector.retrieveCertificate(certificateRequest);
	
	    RevocationRequest revocationRequest = new RevocationRequest();
	    revocationRequest.reason("key-compromise");
	    revocationRequest.certificateDN(certificateRequest.pickupId());
	
	    connector.revokeCertificate(revocationRequest);
	}

	@Test
	@DisplayName("Create a cerfiticate and validate specified validity hours - TPP")
	void createCertificateValidateValidityHours() throws UnknownHostException, VCertException {
	
		TppConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest cr = connectorResource.certificateRequest()
	    		.validityHours(TestUtils.VALID_HOURS)
	    		.issuerHint("MICROSOFT");
	    
	    cr = connector.generateRequest(zoneConfiguration, cr);
	
	    // Submit the certificate request
	    connector.requestCertificate(cr, zoneConfiguration);
	
	    // Retrieve PEM collection from Venafi
	    PEMCollection pemCollection = connector.retrieveCertificate(cr);
	
	    Date notAfter = pemCollection.certificate().getNotAfter();
	    LocalDate notAfterDate = notAfter.toInstant().atOffset(ZoneOffset.UTC).toLocalDate();
	    
	    Instant now = Instant.now();
	    LocalDateTime utcDateTime = LocalDateTime.ofInstant(now, ZoneOffset.UTC);
	
	    int validityDays = VCertUtils.getValidityDays(TestUtils.VALID_HOURS);
	    utcDateTime = utcDateTime.plusDays(validityDays);
	
	    LocalDate nowDateInUTC = utcDateTime.toLocalDate();
	
	    //Dates should be equals if not then it will fail
	    assertTrue(notAfterDate.compareTo(nowDateInUTC) == 0);
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
	    
	    ImportRequest importRequest = new ImportRequest();
	    importRequest.certificateData(cert);
	    importRequest.privateKeyData(pk);
	    importRequest.policyDN(connectorResource.connector().getPolicyDN(TestUtils.TPP_ZONE));
	
	
	    ImportResponse response = connectorResource.connector().importCertificate(importRequest);
	    assertThat(response).isNotNull();
	    assertThat(response.certificateDN()).isNotNull();
	    assertThat(response.certificateVaultId()).isNotNull();
	    assertThat(response.privateKeyVaultId()).isNotNull();
	}
	
	@Test
	void privateKeyPKCSTest() throws VCertException, UnknownHostException, IOException {
		TppConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    
	    //By default the DataFormat of the CertificateRequest is PKCS8
	    CertificateRequest certificateRequest = connectorResource.certificateRequest()
	            .csrOrigin(CsrOriginOption.ServiceGeneratedCSR)
	            .keyPassword(TestUtils.KEY_PASSWORD);
	    
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String pickupId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(pickupId).isNotNull();
	    
	    //Retrieving the PemCollection
	    PEMCollection pemCollectionRSAPrivateKeyPKCS8 = connector.retrieveCertificate(certificateRequest);
	    
	    //getting the PrivateKey as PEM which should be a RSA Private Key in PKCS8 Encrypted
	    String privateKeyPKCS8AsEncryptedPem = pemCollectionRSAPrivateKeyPKCS8.pemPrivateKey();
	    
	    PemObject privateKeyPKCS8AsPemObject = new PemReader(new StringReader(privateKeyPKCS8AsEncryptedPem)).readPemObject();
	    
	    //evaluating that the private Key is in PKCS8 Encrypted
	    assertThat(pemCollectionRSAPrivateKeyPKCS8.privateKey()).isNotNull();
	    assertTrue(privateKeyPKCS8AsPemObject.getType().equals(TestUtils.PEM_HEADER_PKCS8_ENCRYPTED));
	    
	    //changing to data format Legacy in order to get the PrivateKey in PKCS1
	    certificateRequest.dataFormat(DataFormat.LEGACY);
	    
	    //Retrieving the PemCollection
	    PEMCollection pemCollectionRSAPrivateKey = connector.retrieveCertificate(certificateRequest);
	    
	    //getting the PrivateKey as PEM which should be a RSA Private Key Encrypted
	    String privateKeyRSAAsEncryptedPem = pemCollectionRSAPrivateKey.pemPrivateKey();
	    
	    PemObject privateKeyRSAAsPemObject = new PemReader(new StringReader(privateKeyRSAAsEncryptedPem)).readPemObject();
	    
	    //evaluating that the private Key is in PKCS1 Encrypted
	    assertThat(pemCollectionRSAPrivateKey.privateKey()).isNotNull();
	    assertTrue(privateKeyRSAAsPemObject.getHeaders().stream().anyMatch(header -> TestUtils.PEM_RSA_PRIVATE_KEY_ENCRYPTED_HEADER_VALUE.equals(((PemHeader)header).getValue())));
	}

}
