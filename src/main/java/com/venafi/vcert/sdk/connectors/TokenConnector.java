package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

public interface TokenConnector {

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

    //=========================================================================================\\
    //=============================== VENAFI 20.2 TOKEN METHODS ===============================\\
    //=========================================================================================\\

    /**
     * returns a new access token.
     * @param auth authentication info
     * @return the new token.
     * @throws VCertException throws this exception when authentication info is null.
     */
    TokenInfo getAccessToken (Authentication auth ) throws VCertException;

    /**
     * this is for refreshing a token.
     * @param refreshToken the refresh token.
     * @param applicationId the application id.
     * @return a complete info about the new access token, refresh token, expires.
     */
    TokenInfo refreshAccessToken( String refreshToken, String applicationId ) throws VCertException;

    /**
     *
     * @return 1 if the access token was revoked and 0 if not.
     */
    int revokeAccessToken( String accessToken ) throws VCertException;

    /**
     * VedAuth method.
     *
     * Attempt to connect the Venafi API and returns an error if it cannot
     *
     * @throws VCertException
     */
    void ping(String accessToken) throws VCertException;

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
    ZoneConfiguration readZoneConfiguration(String zone, String accessToken) throws VCertException;

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
    CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request, String accessToken)
            throws VCertException;

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
    String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration, String accessToken)
            throws VCertException, UnsupportedOperationException;

    /**
     * VedAuth method.
     *
     * Submits the CSR to Venafi for processing
     *
     * @param request
     * @param zone
     * @param accessToken the authentication token.
     * @return request id to track the certificate status.
     * @throws VCertException
     */
    String requestCertificate(CertificateRequest request, String zone, String accessToken)
            throws VCertException, UnsupportedOperationException;

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
    PEMCollection retrieveCertificate(CertificateRequest request, String accessToken) throws VCertException;

    /**
     * VedAuth method.
     *
     * Attempts to revoke a certificate
     *
     * @param request
     * @param accessToken the authentication token.
     * @throws VCertException
     */
    void revokeCertificate(RevocationRequest request, String accessToken) throws VCertException;

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
    String renewCertificate(RenewalRequest request, String accessToken) throws VCertException;

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
    ImportResponse importCertificate(ImportRequest request, String accessToken) throws VCertException;

    /**
     * VedAuth method.
     *
     * Reads the policy configuration for a specific zone in Venafi
     *
     * @param zone
     * @return
     * @throws VCertException
     */
    Policy readPolicyConfiguration(String zone, String accessToken) throws VCertException;
}
