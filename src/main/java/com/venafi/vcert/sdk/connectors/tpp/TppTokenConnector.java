package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.ConnectorException.FailedToRevokeTokenException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingAccessTokenException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingRefreshTokenException;
import com.venafi.vcert.sdk.connectors.TokenConnector;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import feign.FeignException;
import feign.FeignException.BadRequest;
import feign.FeignException.Unauthorized;
import feign.Response;

import static org.apache.commons.lang3.StringUtils.isBlank;

public class TppTokenConnector extends TppConnector implements TokenConnector {

	private TokenInfo tokenInfo;

	public TppTokenConnector(Tpp tpp){ super(tpp); }

	@Override
	public ConnectorType getType() {
		return ConnectorType.TPP_TOKEN;
	}

	private String getAuthHeaderValue() throws VCertException {
		return getAuthHeaderValue(credentials);
	}

	private String getAuthHeaderValue(Authentication credentials) throws VCertException {
		if( isEmptyAccessToken(credentials) )
			throw new MissingAccessTokenException();

		return String.format(HEADER_VALUE_AUTHORIZATION, credentials.accessToken());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isEmptyCredentials(Authentication credentials){
		if(credentials == null){
			return true;
		}

		return isEmptyTokens(credentials) && (super.isEmptyCredentials(credentials));
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Note: For this implementation is determined if the {@link Authentication#accessToken()} was provided.
	 * If that is the case then it's invoked the {@link Tpp#verifyToken(String)} method to verify if the provided access
	 * Token is valid,
	 * otherwise then the {@link Tpp#authorizeToken(AuthorizeTokenRequest)} is invoked to get the accessToken and
	 * refreshToken which
	 * will be set to the credentials of this instance.
	 * Also the credentials given replaces the credentials hold by this instance until
	 * this moment and additionally the {@link TokenInfo} object is created.
	 *
	 * @throws VCertException if the call to {@link Tpp#authorize(AuthorizeRequest)} throws a {@link Unauthorized} or {@link BadRequest}
	 */
	@Override
	public void authorize(Authentication credentials) throws VCertException {
		//If the AccessToken or RefreshToken were provided then only verify the accessToken is still valid
		if(!isEmptyTokens(credentials)) {
			verifyAccessToken(credentials);
		} else { // The user and password were provided so then generate an accessToken from them
			authorizeToken(credentials);
		}
	}

	private boolean isEmptyTokens( Authentication credentials ){
		return isEmptyAccessToken(credentials) && isBlank(credentials.refreshToken());
	}

	private boolean isEmptyAccessToken(Authentication credentials){
		return credentials == null || isBlank(credentials.accessToken());
	}

	private void verifyAccessToken(Authentication credentials) throws VCertException {
		if(!isBlank(credentials.accessToken())) {

			try {
				//Verify the AccessToken
				tpp.verifyToken(getAuthHeaderValue(credentials));
			} catch (Unauthorized | BadRequest e) {
				throw VCertException.fromFeignException(e);
			}
		}

		this.credentials = credentials;
		this.tokenInfo = null;
	}

	private void authorizeToken(Authentication auth) throws VCertException {
		try {
			AuthorizeTokenRequest authRequest =
					new AuthorizeTokenRequest(auth.user(), auth.password(), auth.clientId(), auth.scope(), auth.state(),
							auth.redirectUri());
			AuthorizeTokenResponse response = tpp.authorizeToken(authRequest);
			tokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(),
					response.tokenType(), response.scope(), response.identity(), response.refreshUntil(), true, null);

			setTokenCredentials(auth);
		} catch(Unauthorized | BadRequest e){
			throw VCertException.fromFeignException(e);
		}
	}

	private void setTokenCredentials(Authentication auth) {
		this.credentials = auth.accessToken(tokenInfo.accessToken()).refreshToken(tokenInfo.refreshToken());
	}

	@Override
	public TokenInfo getTokenInfo() throws VCertException {
		return tokenInfo;
	}

	@Override
	public TokenInfo getAccessToken(Authentication auth) throws VCertException {

		Authentication authTemp = null;

		if (auth != null) {

			// Creating a temp Authentication from the one passed as argument.
			// The Authentication object passed to Connector.authenticate() method requires
			// the accessToken and refreshToken not to be set
			authTemp = Authentication.builder()
					.user(auth.user())
					.password(auth.password())
					.clientId(auth.clientId())
					.scope(auth.scope())
					.state(auth.state())
					.redirectUri(auth.redirectUri())
					.build();
		}

		authenticate(authTemp);

		//setting the auth object as the credentials and setting into it the accessToken
		//and refreshToken hold by TokenInfo
		setTokenCredentials(auth);

		return getTokenInfo();
	}

	@Override
	public TokenInfo getAccessToken() throws VCertException {
		return getAccessToken(credentials);
	}

	@Override
	public TokenInfo refreshAccessToken(String clientId ) throws VCertException{
		if(isBlank(credentials.refreshToken()))
			throw new MissingRefreshTokenException();

		try {
			RefreshTokenRequest request = new RefreshTokenRequest(credentials.refreshToken(), clientId);
			RefreshTokenResponse response = tpp.refreshToken( request );

			tokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(),
					response.tokenType(), response.scope(), "", response.refreshUntil(), true, null);

			this.credentials.accessToken(tokenInfo.accessToken());
			this.credentials.refreshToken(tokenInfo.refreshToken());

			return tokenInfo;
		}catch (FeignException.BadRequest e){
			throw VCertException.fromFeignException(e);
		}
	}

	@Override
	public int revokeAccessToken() throws VCertException {

		String requestHeader = getAuthHeaderValue();//"Bearer "+accessToken;

		Response response = tpp.revokeToken( requestHeader );
		if(response.status() == 200){
			return response.status();
		}else{
			throw new FailedToRevokeTokenException(response.reason());
		}
	}

	@Override
	protected TppAPI getTppAPI() {
		if(tppAPI == null){

			tppAPI = new TppAPI(tpp) {

				@Override
				public String getAuthKey() throws VCertException {
					return getAuthHeaderValue();
				}
			};
		}

		return tppAPI;
	}
}
