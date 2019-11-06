package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

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
   * Attempt to connect the Venafi API and returns an error if it cannot
   * 
   * @throws VCertException
   */
  void ping() throws VCertException;

  /**
   * Authenticate the user with Venafi using either API key for venafi Cloud or user and password
   * for TPP
   * 
   * @param auth
   * @throws VCertException
   */
  void authenticate(Authentication auth) throws VCertException;

  /**
   * Reads the zone configuration needed for generating and requesting a certificate
   * 
   * @param zone
   * @return
   * @throws VCertException
   */
  ZoneConfiguration readZoneConfiguration(String zone) throws VCertException;

  /**
   * GenerateRequest creates a new certificate request, based on the zone/policy configuration and
   * the user data
   * 
   * @param config
   * @return
   * @throws VCertException
   */
  CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request)
      throws VCertException;

  /**
   * Submits the CSR to venafi for processing
   * 
   * @param request
   * @param zone
   * @return request id to track the certificate status.
   * @throws VCertException
   */
  String requestCertificate(CertificateRequest request, String zone) throws VCertException;

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
   * Import an external certificate into venafi.
   * 
   * @param request
   * @return
   * @throws VCertException
   */
  ImportResponse importCertificate(ImportRequest request) throws VCertException;

  /**
   * Reads the policy configuration for a specific zone in venafi
   * 
   * @param zone
   * @return
   * @throws VCertException
   */
  Policy readPolicyConfiguration(String zone) throws VCertException;
}
