package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingCredentialsException;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;


/**
 * 
 * This represents the connector to TPP or Cloud 
 *
 */
public interface Connector extends ISSHConnector, IPMConnector{

	Authentication getCredentials();

	/**
	 * @return ConnectorType the type of connector Cloud or TPP
	 */
	ConnectorType getType();

	/**
	 * Allows overriding the default URL used to communicate with Venafi
	 * 
	 * @param url
	 * @throws VCertException
	 */
	void setBaseUrl(String url) throws VCertException;

	/**
	 * Set the default zone
	 * 
	 * @param zone
	 */
	void setZone(String zone);

	/**
	 * Set the vendor and product name
	 * 
	 * @param vendorAndProductName
	 */
	void setVendorAndProductName(String vendorAndProductName);

	/**
	 * @return the vendor and product name
	 */
	String getVendorAndProductName();

	/**
	 * Attempt to connect the Venafi API and returns an error if it cannot
	 * 
	 * @throws VCertException
	 */
	void ping() throws VCertException;

	/**
	 * This is the default implementation which provides a mechanism to authenticate the credentials
	 *  provided in the {@link Authentication} object.
	 * Behind the scene, it's validating if the credentials were provided calling the 
	 * {@link #isEmptyCredentials(Authentication)} method and if that returns true, then a {@link MissingCredentialsException} 
	 * is thrown. If the credentials are not empty then is called the {@link #authorize(Authentication)} method.
	 * 
	 * @param credentials
	 * @throws VCertException
	 */
	default void authenticate(Authentication credentials) throws VCertException {

		if(isEmptyCredentials(credentials)) 
			throw new MissingCredentialsException();

		authorize(credentials);
	}

	/**
	 * Determines if the given credentials object is empty or not. This method is used by {@link #authenticate(Authentication)} 
	 * method to determine if the credentials were provided in order to after invoke the {@link #authorize(Authentication)} 
	 * method.
	 * @param credentials
	 * @return
	 */
	boolean isEmptyCredentials(Authentication credentials);
	
	/**
	 * Performs the authorization actions using the credentials provided. This method is used by {@link #authenticate(Authentication)} 
	 * method after the credentials were validated as not empty.
	 * @param credentials
	 * @throws VCertException
	 */
	void authorize(Authentication credentials) throws VCertException;

	/**
	 * Reads the zone configuration needed for generating and requesting a certificate
	 * 
	 * @param zone ID (e.g. 2ebd4ec1-57f7-4994-8651-e396b286a3a8) or zone path (e.g.
	 *        "ProjectName\ZoneName")
	 * @return
	 * @throws VCertException
	 */
	ZoneConfiguration readZoneConfiguration(String zone) throws VCertException;

	/**
	 * GenerateRequest creates a new certificate request, based on the zone/policy configuration and
	 * the user data
	 * 
	 * @param config
	 * @return the zone configuration
	 * @throws VCertException
	 */
	CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request)
			throws VCertException;

	/**
	 * Submits the CSR to Venafi for processing
	 * 
	 * @param request
	 * @param zoneConfiguration
	 * @return request id to track the certificate status.
	 * @throws VCertException
	 */
	String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration)
			throws VCertException;

	/**
	 * Submits the CSR to Venafi for processing
	 * 
	 * @param request
	 * @param zone
	 * @return request id to track the certificate status.
	 * @throws VCertException
	 */
	String requestCertificate(CertificateRequest request, String zone)
			throws VCertException;

	/**
	 * Retrieves the certificate for the specific ID
	 * 
	 * @param request
	 * @return A collection of PEM files including certificate, chain and potentially a private key.
	 * @throws VCertException
	 */
	PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException;

	/**
	 * Attempts to revoke a certificate
	 * 
	 * @param request
	 * @throws VCertException
	 */
	void revokeCertificate(RevocationRequest request) throws VCertException;

	/**
	 * Attempts to renew a certificate
	 * 
	 * @param request
	 * @return
	 * @throws VCertException
	 */
	String renewCertificate(RenewalRequest request) throws VCertException;

	/**
	 * Import an external certificate into Venafi.
	 * 
	 * @param request
	 * @return
	 * @throws VCertException
	 */
	ImportResponse importCertificate(ImportRequest request) throws VCertException;
}
