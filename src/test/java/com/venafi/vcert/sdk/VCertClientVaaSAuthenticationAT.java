/**
 * 
 */
package com.venafi.vcert.sdk;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.venafi.vcert.sdk.connectors.ConnectorException.MissingCredentialsException;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

import feign.FeignException.Unauthorized;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class VCertClientVaaSAuthenticationAT {

	@Test
	void authenticationInConstructor() {
		//Testing the creation of a VCertClient passing a Config Object with an Authentication
		//object with Api Key, which will cause the authentication at the moment that 
		// the VCertClient object is created
		
		getClientAuthenticatedByAPIKey();
	}
	
	@Test
	void authenticationAfterConstructor() {
		//Testing the authentication of a VCertClient through of the use of authentication() method
		
		// expecting that the VCertClient will be created
		VCertClient client = getClientUnauthenticated();
		
		//expecting that the authentication will be performed correctly
		assertDoesNotThrow( () -> client.authenticate( getAPIKeyAuthentication() ) );
	}
	
	@Test
	void invalidAuthenticationMissingCredentialsInConstructor() {
		
		//Invalid Authentication object provided to the Config object.
		
		//asserting that credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> new VCertClient( getConfig( getAuthenticationMissingAPIKey()) ));
	}
	
	@Test
	void unauthorizedAuthenticationInConstructor() {
		
		//Unauthorized Authentication object provided to the Config object.

		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> new VCertClient( getConfig( getAuthenticationUnauthorizedAPIKey() ) ) )
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	@Test
	void invalidAuthenticationMissingCredentialsAfterConstructor() {
		
		//Invalid Authentication object provided to the authenticate method.

		//asserting that the Client was created
		VCertClient client = getClientUnauthenticated();

		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.authenticate( getAuthenticationMissingAPIKey() ));
	}
	
	@Test
	void unauthorizedAuthenticationAfterConstructor() {
		
		//asserting that the Client was created
		VCertClient client = getClientUnauthenticated();

		//Unauthorized Authentication object provided to the authenticate method.

		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> client.authenticate( getAuthenticationUnauthorizedAPIKey() ) )
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	private VCertClient getClientAuthenticatedByAPIKey() {
		// if the authentication was performed successfully, then the VCertClient will be created
		return assertDoesNotThrow( () -> new VCertClient( getConfig( getAPIKeyAuthentication() ) ) );
	}
	
	private VCertClient getClientUnauthenticated() {
		//A null Authentication object was provided to the Config object.
		//asserting that credentials were not provided
		return assertDoesNotThrow(() -> new VCertClient( getConfig(null) ) );
	}
	
	private Authentication getAPIKeyAuthentication() {
		return Authentication.builder()
				.apiKey(TestUtils.API_KEY)
				.build();
	}
	
	private Authentication getAuthenticationMissingAPIKey() {
		return Authentication.builder().apiKey("").build();
	}
	
	private Authentication getAuthenticationUnauthorizedAPIKey() {
		return Authentication.builder().apiKey("12345").build();
	}
	
	private Config getConfig(Authentication authentication) {
		return Config.builder()
				.connectorType(ConnectorType.CLOUD)
				.credentials(authentication)
				.build();
	}
}
