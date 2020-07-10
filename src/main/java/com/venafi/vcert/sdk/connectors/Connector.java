package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

public interface Connector {

   public final String NOT_IMPLEMENTED_STRING = "Method not yet implemented.";

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
  default void ping() throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Authenticate the user with Venafi using either API key for Venafi Cloud or user and password
   * for TPP
   * 
   * @param auth
   * @throws VCertException
   */
  default void authenticate(Authentication auth) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Reads the zone configuration needed for generating and requesting a certificate
   * 
   * @param zone ID (e.g. 2ebd4ec1-57f7-4994-8651-e396b286a3a8) or zone path (e.g.
   *        "ProjectName\ZoneName")
   * @return
   * @throws VCertException
   */
  default ZoneConfiguration readZoneConfiguration(String zone) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * GenerateRequest creates a new certificate request, based on the zone/policy configuration and
   * the user data
   * 
   * @param config
   * @return the zone configuration
   * @throws VCertException
   */
  default CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request)
      throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Submits the CSR to Venafi for processing
   * 
   * @param request
   * @param zoneConfiguration
   * @return request id to track the certificate status.
   * @throws VCertException
   */
  default String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration)
      throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Submits the CSR to Venafi for processing
   * 
   * @param request
   * @param zone
   * @return request id to track the certificate status.
   * @throws VCertException
   */
  default String requestCertificate(CertificateRequest request, String zone)
      throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Retrives the certificate for the specific ID
   * 
   * @param request
   * @return A collection of PEM files including certificate, chain and potentially a private key.
   * @throws VCertException
   */
  default PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Attempts to revoke a certificate
   * 
   * @param request
   * @throws VCertException
   */
  default void revokeCertificate(RevocationRequest request) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Attempts to renew a certificate
   * 
   * @param request
   * @return
   * @throws VCertException
   */
  default String renewCertificate(RenewalRequest request) throws VCertException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Import an external certificate into Venafi.
   * 
   * @param request
   * @return
   * @throws VCertException
   */
  default ImportResponse importCertificate(ImportRequest request) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException(NOT_IMPLEMENTED_STRING);
  }

  /**
   * Reads the policy configuration for a specific zone in Venafi
   * 
   * @param zone
   * @return
   * @throws VCertException
   */
  Policy readPolicyConfiguration(String zone) throws VCertException;

  /**
   *
   * @return 1 if the access token was revoked and 0 if not.
   * @throws OperationNotSupportedException for some types of applications this is not valid.
   */
  default int revokeAccessToken( String accessToken ) throws OperationNotSupportedException {
	  throw new OperationNotSupportedException();
  }

  /**
   * returns a new access token.
   * @param auth authentication info
   * @return the new token.
   * @throws OperationNotSupportedException for some types of applications this is not valid.
   * @throws VCertException throws this exception when authentication info is null.
   */
  default TokenInfo getAccessToken ( Authentication auth ) throws OperationNotSupportedException, VCertException {
	  throw new OperationNotSupportedException();
  }

  /**
   * this is for refreshing a token.
   * @param resfreshToken the refresh token.
   * @param applicationId the application id.
   * @return a complete info about the new access token, refresh token, expires.
   * @throws javax.naming.OperationNotSupportedException
   */
  default TokenInfo refreshToken( String resfreshToken, String applicationId ) throws OperationNotSupportedException{
	  throw new OperationNotSupportedException();
  }

  //=========================================================================================\\
  //=============================== VENAFI 20.2 VEDAUTH METHODS ===============================\\
  //=========================================================================================\\

  /**
   * VedAuth method.
   *
   * Attempt to connect the Venafi API and returns an error if it cannot
   *
   * @throws VCertException
   * @throws UnsupportedOperationException
   */
  default void ping(String accessToken) throws VCertException, UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   * Reads the zone configuration needed for generating and requesting a certificate
   *
   * @param zone ID (e.g. 2ebd4ec1-57f7-4994-8651-e396b286a3a8) or zone path (e.g.
   *        "ProjectName\ZoneName")
   * @param accessToken The authentication token.
   * @return
   * @throws VCertException
   */
  default ZoneConfiguration readZoneConfiguration(String zone, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * GenerateRequest creates a new certificate request, based on the zone/policy configuration and
   * the user data
   *
   * @param config
   * @param accessToken The authentication token
   * @return the zone configuration
   * @throws VCertException
   */
  default CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request, String accessToken)
          throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  };

  /**
   * VedAuth method.
   *
   * Submits the CSR to Venafi for processing
   *
   * @param request
   * @param zoneConfiguration
   * @param accessToken the authentication token.
   * @return request id to track the certificate status.
   * @throws VCertException
   */
  default String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration, String accessToken)
          throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Submits the CSR to Venafi for processing
   *
   * @param request
   * @param zone
   * @param accesToken the authentication token.
   * @return request id to track the certificate status.
   * @throws VCertException
   */
  default String requestCertificate(CertificateRequest request, String zone, String accesToken)
          throws VCertException, UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Retrives the certificate for the specific ID
   *
   * @param request
   * @param accessToken the authentication token.
   * @return A collection of PEM files including certificate, chain and potentially a private key.
   * @throws VCertException
   */
  default PEMCollection retrieveCertificate(CertificateRequest request, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Attempts to revoke a certificate
   *
   * @param request
   * @param accessToken the authentication token.
   * @throws VCertException
   */
  default void revokeCertificate(RevocationRequest request, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Attempts to renew a certificate
   *
   * @param request
   * @param accessToken the authentication token.
   * @return
   * @throws VCertException
   */
  default String renewCertificate(RenewalRequest request, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Import an external certificate into Venafi.
   *
   * @param request
   * @param accessToken the authentication token.
   * @return
   * @throws VCertException
   */
  default ImportResponse importCertificate(ImportRequest request, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

  /**
   * VedAuth method.
   *
   * Reads the policy configuration for a specific zone in Venafi
   *
   * @param zone
   * @return
   * @throws VCertException
   */
  default Policy readPolicyConfiguration(String zone, String accessToken) throws VCertException, UnsupportedOperationException{
    throw new UnsupportedOperationException();
  }

}
