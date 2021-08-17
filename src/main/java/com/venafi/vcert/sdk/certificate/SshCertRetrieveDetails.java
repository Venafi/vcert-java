package com.venafi.vcert.sdk.certificate;

import lombok.Data;

/*
 * This documentation is based on the documentation on https://jira.eng.venafi.com/browse/VEN-64863
 */

/**
 * This class represents the Response Object to use to "retrieve" a requested SSH Certificate.
 * </br> </br>
 * For more information related to the "Retrieve SSH Certificates" action see 
 * {@link com.venafi.vcert.sdk.VCertClient#retrieveSshCertificate(SshCertificateRequest) VCertClient.retrieveSshCertificate(SshCertificateRequest)} or  
 * {@link com.venafi.vcert.sdk.VCertTknClient#retrieveSshCertificate(SshCertificateRequest) VCertTknClient.retrieveSshCertificate(SshCertificateRequest)} 
 * 
 * @author Marcos E. Albornoz Abud
 */
@Data
public class SshCertRetrieveDetails {

	/**
	 * A value that uniquely identifies the certificate request.
	 */
	private String guid;
	/**
	 * The DN of the created SSH certificate object.
	 */
	private String dn;
	/**
	 * Unique identifier of the CA used to sign the requested certificate.
	 */
	private String caGuid;
	/**
	 * The DN of the CA used to sign the requested certificate.
	 */
	private String cadn;
	/**
	 * Base-64 encoded string of the issued certificate which can be directly consumed by SSH clients.
	 */
	private String certificateData;
	/**
	 * The private key in base-64 encoded PEM/OpenSSH format which can be directly consumed by SSH clients. 
	 * If passphrase is specified in the request, then the key is encrypted. Included only when IncludePrivateKeyData is True.
	 */
	private String privateKeyData;
	/**
	 * The public key in base-64 encoded OpenSSH format which can be directly consumed by SSH clients. 
	 * Included only when IncludePrivateKeyData is True.
	 */
	private String publicKeyData;
	
	/*
	 * NOTE: In the official documentation on https://jira.eng.venafi.com/browse/VEN-64863
	 * is commented that "It will be included in the response only when IncludeCertificateDetails 
	 * parameter of the request is True", but given that is always true for VCert-Java, then this 
	 * will be included always. 
	 */
	/**
	 * The details of the issues certificate
	 */
	private SshCertificateDetails certificateDetails;
}
