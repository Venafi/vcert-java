package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;


/**
 * 
 * This represents the connector to TPP or Cloud 
 *
 */
public interface Connector {

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
   * Authenticate the user with Venafi using either API key for Venafi Cloud or user and password
   * for TPP
   * 
   * @param auth
   * @throws VCertException
   */
  void authenticate(Authentication auth) throws VCertException;

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
   * Retrives the certificate for the specific ID
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

  /**
   * Reads the policy configuration for a specific zone in Venafi
   * 
   * @param zone
   * @return
   * @throws VCertException
   */
  Policy readPolicyConfiguration(String zone) throws VCertException;

  /**
   * Create/update a policy based on the policySpecification passed as argument.
   * 
   * @param policyName
   * @param policySpecification
   * @throws VCertException
   */
  void setPolicy(String policyName, PolicySpecification policySpecification) throws VCertException;

  /**
   * Returns the policySpecification from the policy which matches with the policyName argument.
   * 
   * @param policyName
   * @return
   * @throws VCertException
   */
  PolicySpecification getPolicy(String policyName) throws VCertException;
  
  /**
   * Request a new SSH Certificate.
   * @param sshCertificateRequest The {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest} instance needed to do the request. 
   * For more information about of which properties should be filled, please review the documentation of 
   * {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest}.
   * @return The DN of the created SSH certificate object. It can be used as pickup ID to retrieve the created SSH Certificate. 
   * For more details review the {@link #retrieveSshCertificate(SshCertificateRequest) retrieveSshCertificate(SshCertificateRequest)} method.
   * @throws VCertException 
   */
  String requestSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException;
  
  /**
   * Retrieve a requested SSH Certificate
   * @param sshCertificateRequest The {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest} instance needed to do the request. 
   * </br>It's mandatory to set the PickUpID which is the value of the DN returned when the SSH Certificate was requested.
   * For more information about of which properties should be filled, please review the documentation of 
   * {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest}.
   * @return A {@link com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails SshCertRetrieveDetails} containing the Certificate Data of the created Certificate.
   * @throws VCertException
   */
  SshCertRetrieveDetails retrieveSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException;
}
