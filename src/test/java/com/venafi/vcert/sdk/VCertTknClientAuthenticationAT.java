/**
 * 
 */
package com.venafi.vcert.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.venafi.vcert.sdk.connectors.ConnectorException.MissingCredentialsException;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

import feign.FeignException.BadRequest;
import feign.FeignException.Unauthorized;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class VCertTknClientAuthenticationAT {
	
	@Test
	void creationWithoutAuthentication() {
		getClientUnauthenticated();
	}
	
	@Test
	void authenticationWithUserPasswordInConstructor() {
		// if the authentication was performed successfully, then the VCertTknClient will be created
		VCertTknClient client = getClientAuthenticatedByUserPassword();
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());

		assertThat(tokenInfo).isNotNull();
		assertThat(tokenInfo.accessToken()).isNotNull();
		assertThat(tokenInfo.refreshToken()).isNotNull();
		
		//revoking the token
		revokeAccessToken(client);
	}
	
	@Test
	void authenticationWithAccessTokenInConstructor() {
		// if the authentication was performed successfully, then the VCertTknClient will be created
		VCertTknClient client = getClientAuthenticatedByUserPassword();
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());
		
		VCertTknClient client2 = getClientAuthenticatedByAccessToken(tokenInfo.accessToken());
		TokenInfo tokenInfo2 = assertDoesNotThrow( () -> client2.getTokenInfo());

		//Asserting that the token info in the client2 was not created given the Authentication provided
		// has set the accessToken, meaning that only a verify action to validate it is performed
		assertThat(tokenInfo2).isNull();
		
		//revoking the token
		revokeAccessToken(client);
	}
	
	@Test
	void authenticationWithUserPasswordAfterConstructor() {
		
		// Getting client unauthenticated
		VCertTknClient client = getClientUnauthenticated();
		
		//Getting the tokenInfo 
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());
		
		//asserting token info is null
		assertThat(tokenInfo).isNull();
		
		//Authenticating
		assertDoesNotThrow( () -> client.authenticate( getUserPasswordAuthentication() ) );
		
		//Getting the tokenInfo 
		tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());

		assertThat(tokenInfo).isNotNull();
		assertThat(tokenInfo.accessToken()).isNotNull();
		assertThat(tokenInfo.refreshToken()).isNotNull();
		
		//revoking the token
		revokeAccessToken(client);
	}
	
	@Test
	void authenticationWithAccessTokenAfterConstructor() {
		
		// Getting client unauthenticated
		VCertTknClient client = getClientUnauthenticated();
		
		//Authenticating
		assertDoesNotThrow( () -> client.authenticate( getUserPasswordAuthentication() ) );
		
		//Getting the tokenInfo 
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());
		
		// Getting client unauthenticated
		VCertTknClient client2 = getClientUnauthenticated();
		
		//Authenticating
		assertDoesNotThrow( () -> client2.authenticate( getAccessTokenAuthentication(tokenInfo.accessToken()) ) );

		TokenInfo tokenInfo2 = assertDoesNotThrow( () -> client2.getTokenInfo());
		//Asserting that the token info in the client2 was not created given the Authentication provided
		// has set the accessToken, meaning that only a verify action to validate it is performed
		assertThat(tokenInfo2).isNull();
		
		//revoking the token
		revokeAccessToken(client);
	}
	
	@Test
	void getAccessTokenFromClientAuthenticatedByUserPassword() {
		
		VCertTknClient client = getClientAuthenticatedByUserPassword();
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getTokenInfo());
		
		assertThat(tokenInfo).isNotNull();
		assertThat(tokenInfo.accessToken()).isNotNull();
		assertThat(tokenInfo.refreshToken()).isNotNull();
		
		revokeAccessToken(client);
		
		//CASE 1 - Testing the behavior of VCertTknClient.accessToken() when the authentication it was provided previously.
		
		//Requesting the AccessToken. This will cause that the token be requested again replacing the previous one gotten
		// at the creation of the client
		TokenInfo tokenInfo2 = assertDoesNotThrow( () -> client.getAccessToken());
		
		assertThat(tokenInfo2).isNotNull();
		assertThat(tokenInfo2.accessToken()).isNotNull();
		assertThat(tokenInfo2.refreshToken()).isNotNull();
		
		//ensuring that the TokenInfo and TokenInfo2 are not the same object.
		assertNotSame(tokenInfo, tokenInfo2);
		
		revokeAccessToken(client);
		
		//CASE 2 - Testing the behavior of VCertTknClient.accessToken(Authentication) when the authentication 
		//it was provided previously.

		//Requesting the AccessToken. This will cause that the token be requested again replacing the previous one gotten
		TokenInfo tokenInfo3 = assertDoesNotThrow( () -> client.getAccessToken( getUserPasswordAuthentication() ));
		
		assertThat(tokenInfo3).isNotNull();
		assertThat(tokenInfo3.accessToken()).isNotNull();
		assertThat(tokenInfo3.refreshToken()).isNotNull();

		//ensuring that the TokenInfo and TokenInfo3 are not the same object.
		assertNotSame(tokenInfo, tokenInfo3);
		//ensuring that the TokenInfo2 and TokenInfo3 are not the same object.
		assertNotSame(tokenInfo2, tokenInfo3);
		
		revokeAccessToken(client);
	}
	
	@Test
	void getAccessTokenFromClientUnauthenticated() {
		
		VCertTknClient client = getClientUnauthenticated();
		TokenInfo tokenInfo = assertDoesNotThrow( () -> client.getAccessToken( getUserPasswordAuthentication()));
		
		assertThat(tokenInfo).isNotNull();
		assertThat(tokenInfo.accessToken()).isNotNull();
		assertThat(tokenInfo.refreshToken()).isNotNull();
		
		revokeAccessToken(client);
	}
	
	@Test
	void invalidUserPasswordAuthenticationMissingCredentialsInConstructor() {
		invalidAuthenticationMissingCredentialsInConstructor(getAuthenticationMissingUserPassword());
	}
	
	@Test
	void unauthorizedUserPasswordAuthenticationInConstructor() {
		badRequestAuthenticationInConstructor(getAuthenticationUnauthorizedUserPassword());
	}
	
	@Test
	void invalidAccessTokenAuthenticationMissingCredentialsInConstructor() {
		invalidAuthenticationMissingCredentialsInConstructor(getAuthenticationMissingAccessToken());
	}
	
	@Test
	void unauthorizedAccessTokenAuthenticationInConstructor() {
		unauthorizedAuthenticationInConstructor(getAuthenticationUnauthorizedAccessToken());
	}
	
	@Test
	void invalidUserPasswordAuthenticationMissingCredentialsAfterConstructor() {
		invalidAuthenticationMissingCredentialsAfterConstructor(getAuthenticationMissingUserPassword());
	}
	
	@Test
	void unauthorizedUserPasswordAuthenticationAfterConstructor() {
		badRequestAuthenticationAfterConstructor(getAuthenticationUnauthorizedUserPassword());
	}
	
	@Test
	void invalidAccessTokenAuthenticationMissingCredentialsAfterConstructor() {
		invalidAuthenticationMissingCredentialsAfterConstructor(getAuthenticationMissingAccessToken());
	}
	
	@Test
	void unauthorizedAccessTokenAuthenticationAfterConstructor() {
		unauthorizedAuthenticationAfterConstructor(getAuthenticationUnauthorizedAccessToken());
	}
	
	@Test
	void invalidAuthenticationMissingCredentialsInAccessToken() {
		
		VCertTknClient client = getClientUnauthenticated();
		
		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.getAccessToken());
		
		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.getAccessToken(getAuthenticationMissingAccessToken()));
		
		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.getAccessToken(getAuthenticationUnauthorizedAccessToken()));
	}
	
	private VCertTknClient getClientAuthenticatedByUserPassword() {
		// if the authentication was performed successfully, then the VCertTknClient will be created
		return assertDoesNotThrow( () -> new VCertTknClient( getConfig( getUserPasswordAuthentication() ) ) );
	}
	
	private VCertTknClient getClientAuthenticatedByAccessToken(String accessToken) {
		// if the authentication was performed successfully, then the VCertTknClient will be created
		return assertDoesNotThrow( () -> new VCertTknClient( getConfig( getAccessTokenAuthentication(accessToken) ) ) );
	}
	
	private VCertTknClient getClientUnauthenticated() {
		//A null Authentication object was provided to the Config object.
		//asserting that credentials were not provided
		return assertDoesNotThrow(() -> new VCertTknClient( getConfig(null) ) );
	}
	
	private void revokeAccessToken( VCertTknClient client ) {
		//revoking the token and asserting that returned result is 200 = Ok
		int revokeAccessTokenResponse = assertDoesNotThrow( () -> client.revokeAccessToken());
		assertEquals(200, revokeAccessTokenResponse);
	}
	
	private Authentication getUserPasswordAuthentication() {
		return Authentication.builder()
				.user(TestUtils.TPP_USER)
				.password(TestUtils.TPP_PASSWORD)
				//.scope("certificate:manage,revoke,discover;configuration:manage")
				.build();
	}
	
	private Authentication getAccessTokenAuthentication(String accessToken) {
		return Authentication.builder()
				.accessToken(accessToken)
				.build();
	}
	
	private Authentication getAuthenticationMissingAccessToken() {
		return Authentication.builder().accessToken("").build();
	}
	
	private Authentication getAuthenticationUnauthorizedAccessToken() {
		return Authentication.builder().accessToken("abcde").build();
	}
	
	private Authentication getAuthenticationMissingUserPassword() {
		return Authentication.builder().user("").password("").build();
	}
	
	private Authentication getAuthenticationUnauthorizedUserPassword() {
		return Authentication.builder().user("user").password("password").build();
	}
	
	private Config getConfig(Authentication authentication) {
		return Config.builder()
				.connectorType(ConnectorType.TPP_TOKEN)
				.baseUrl(TestUtils.TPP_TOKEN_URL)
				.credentials(authentication)
				.build();
	}
	
	private void invalidAuthenticationMissingCredentialsInConstructor(Authentication authentication) {
		
		Config config = getConfig(authentication);
		
		//Invalid Authentication object provided to the Config object.
		//asserting that credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> new VCertTknClient(config) );
	}
	
	private void unauthorizedAuthenticationInConstructor(Authentication authentication) {
		
		Config config = getConfig(authentication);

		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> new VCertTknClient(config))
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	private void badRequestAuthenticationInConstructor(Authentication authentication) {
		
		Config config = getConfig(authentication);

		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> new VCertTknClient(config))
		.withRootCauseInstanceOf(BadRequest.class);
	}
	
	private void invalidAuthenticationMissingCredentialsAfterConstructor(Authentication authentication) {
		
		VCertTknClient client = getClientUnauthenticated();
		
		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.authenticate(authentication));
	}
	
	private void unauthorizedAuthenticationAfterConstructor(Authentication authentication) {
		
		VCertTknClient client = getClientUnauthenticated();
		
		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> client.authenticate(authentication) )
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	private void badRequestAuthenticationAfterConstructor(Authentication authentication) {
		
		VCertTknClient client = getClientUnauthenticated();
		
		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> client.authenticate(authentication) )
		.withRootCauseInstanceOf(BadRequest.class);
	}

}
