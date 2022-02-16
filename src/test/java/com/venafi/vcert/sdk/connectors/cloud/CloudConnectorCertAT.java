/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.net.UnknownHostException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;
import com.venafi.vcert.sdk.certificate.DataFormat;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.ConnectorException.CertificateNotFoundByThumbprintException;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.utils.VCertUtils;


/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class CloudConnectorCertAT {
	
	private static final Logger logger = LoggerFactory.getLogger(CloudConnectorAT.class);
	
	@RegisterExtension
	public final CloudConnectorCertResource connectorResource = new CloudConnectorCertResource();

	@Test
	void requestCertificate() throws VCertException, UnknownHostException {
	    CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connector.generateRequest(zoneConfiguration, connectorResource.certificateRequest());
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	}

	@Test
	void renewCertificate() throws VCertException, UnknownHostException,
	        CertificateException {
		CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connector.generateRequest(zoneConfiguration, connectorResource.certificateRequest());
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	    X509Certificate cert = (X509Certificate) pemCollection.certificate();
	
	    String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();
	
	    CertificateRequest certificateRequestToRenew = new CertificateRequest()
	            .subject(certificateRequest.subject())
	            .dnsNames(certificateRequest.dnsNames());
	    connector.generateRequest(zoneConfiguration, certificateRequestToRenew);
	
	    String renewRequestId = null;
	    try {
	    	renewRequestId = connector.renewCertificate(
	                new RenewalRequest().request(certificateRequestToRenew).thumbprint(thumbprint));
	    } catch (CertificateNotFoundByThumbprintException e) {
			//wait for 5 sec, it's very probably that the Certificate is not ready at this point
	    	logger.warn("Failed to renewCertificate, because it's very probably that the Certificate is not ready yet. Waiting 5 sec to attempt one more time...");
	    	try {
				Thread.sleep(5000);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
	    	renewRequestId = connector.renewCertificate(
	                new RenewalRequest().request(certificateRequestToRenew).thumbprint(thumbprint));
		} 
	
	    assertThat(renewRequestId).isNotNull();
	}
	
	@Test
	void retrieveCertificateServiceGeneratedCSR() throws VCertException, UnknownHostException {
		CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest()
	            .csrOrigin(CsrOriginOption.ServiceGeneratedCSR)
	            .keyPassword(TestUtils.KEY_PASSWORD);
	
	    //For CSR Service Generated Request is not needed to call to generateRequest() method
	    //certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String pickupId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(pickupId).isNotNull();
	
	    certificateRequest.pickupId(pickupId);
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	
	    assertThat(pemCollection.certificate()).isNotNull();
	    assertThat(pemCollection.chain()).hasSize(2);
	    assertThat(pemCollection.privateKey()).isNotNull();
	}
	
	@Test
	void privateKeyPKCSTest() throws VCertException, UnknownHostException, IOException {
		CloudConnector connector = connectorResource.connector();
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

	@Test
	void requestCertificateUnrestricted() throws VCertException, UnknownHostException {
		CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest()
	            .keyType(KeyType.RSA)
	            .keyLength(2048);
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	}

	@Test
	void retrieveCertificateCSRProvided() throws VCertException, UnknownHostException {
		CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest()
	            .keyType(KeyType.RSA);
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    String certificateId = connector.requestCertificate(certificateRequest, zoneConfiguration);
	    assertThat(certificateId).isNotNull();
	
	    certificateRequest.pickupId(certificateId);
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	
	    assertThat(pemCollection.certificate()).isNotNull();
	    assertThat(pemCollection.chain()).hasSize(2);
	    assertThat(pemCollection.privateKey()).isNotNull();
	}

	@Test
	void revokeCertificate() throws VCertException {
	    assertThrows(UnsupportedOperationException.class, () -> {
	    	connectorResource.connector().revokeCertificate(new RevocationRequest());
	    });
	}

	@Test
	@DisplayName("Create a certificate and validate specified validity hours - Cloud")
	public void createCertificateValidateValidityHours() throws VCertException {
	
		CloudConnector connector = connectorResource.connector();
	    ZoneConfiguration zoneConfiguration = connectorResource.zoneConfiguration();
	    CertificateRequest certificateRequest = connectorResource.certificateRequest()
	            .keyType(KeyType.RSA)
	            .validityHours(TestUtils.VALID_HOURS);
	
	    certificateRequest = connector.generateRequest(zoneConfiguration, certificateRequest);
	    connector.requestCertificate(certificateRequest, zoneConfiguration);
	
	    // Retrieve PEM collection from Venafi
	    PEMCollection pemCollection = connector.retrieveCertificate(certificateRequest);
	
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

}
