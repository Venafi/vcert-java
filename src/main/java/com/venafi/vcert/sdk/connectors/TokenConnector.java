package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;

/**
 * This represents the connector to TPP to be used with an access token.
 *
 */
public interface TokenConnector extends Connector{
	
	TokenInfo getTokenInfo() throws VCertException;

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
     * returns a new access token. This method uses the {@link Authentication} object passed earlier
     * with the {@link Config} object.
     * @return the new token.
     * @throws VCertException throws this exception when authentication info is null.
     */
    TokenInfo getAccessToken () throws VCertException;

    /**
     * this is for refreshing a token.
     * @param applicationId the application id.
     * @return a complete info about the new access token, refresh token, expires.
     */
    TokenInfo refreshAccessToken(String applicationId ) throws VCertException;

    /**
     *
     * @return 1 if the access token was revoked and 0 if not.
     */
    int revokeAccessToken() throws VCertException;
}
