/**
 * 
 */
package com.venafi.vcert.sdk;

import static org.assertj.core.api.Assertions.assertThat;
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
public class VCertClientTppAuthenticationAT {

	@Test
	void authenticationInConstructor() {
		//Testing the creation of a VCertClient passing a Config Object with an Authentication
		//object with User and Password, which will cause the authentication at the moment that 
		// the VCertClient object is created
		
		// if the authentication was performed successfully, then the VCertClient will be created
		VCertClient client = getClientAuthenticatedByUserPassword();
		
		// The apiKey shouldn't be null
		assertThat(client.getCredentials().apiKey()).isNotNull();
	}
	
	@Test
	void authenticationAfterConstructor() {
		//Testing the authentication of a VCertClient through of the use of authentication() method
		
		// expecting that the VCertClient will be created
		VCertClient client = getClientUnauthenticated();
		
		//expecting that the authentication will be performed correctly
		assertDoesNotThrow( () -> client.authenticate( getUserPasswordAuthentication() ) );
		
		// The apiKey shouldn't be null
		assertThat(client.getCredentials().apiKey()).isNotNull();
	}
	
	@Test
	void invalidAuthenticationMissingCredentialsInConstructor() {
		
		//Invalid Authentication object provided to the Config object.
		
		//asserting that credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> new VCertClient( getConfig( getAuthenticationMissingUserPassword()) ));
	}
	
	@Test
	void unauthorizedAuthenticationInConstructor() {
		
		//Unauthorized Authentication object provided to the Config object.
		
		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> new VCertClient( getConfig( getAuthenticationUnauthorizedUserPassword() ) ) )
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	@Test
	void invalidAuthenticationMissingCredentialsAfterConstructor() {
		
		//Invalid Authentication object provided to the authenticate method.
		
		//asserting that the Client was created
		VCertClient client = getClientUnauthenticated();
		
		//asserting that the credentials were not provided
		assertThrows(MissingCredentialsException.class, () -> client.authenticate( getAuthenticationMissingUserPassword() ));
	}
	
	@Test
	void unauthorizedAuthenticationAfterConstructor() {
		
		//asserting that the Client was created
		VCertClient client = getClientUnauthenticated();
		
		//Unauthorized Authentication object provided to the authenticate method.
		
		//asserting that the credentials are not valid
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> client.authenticate( getAuthenticationUnauthorizedUserPassword() ) )
		.withRootCauseInstanceOf(Unauthorized.class);
	}
	
	private VCertClient getClientAuthenticatedByUserPassword() {
		// if the authentication was performed successfully, then the VCertClient will be created
		return assertDoesNotThrow( () -> new VCertClient( getConfig( getUserPasswordAuthentication() ) ) );
	}
	
	private VCertClient getClientUnauthenticated() {
		//A null Authentication object was provided to the Config object.
		//asserting that credentials were not provided
		return assertDoesNotThrow(() -> new VCertClient( getConfig(null) ) );
	}
	
	private Authentication getUserPasswordAuthentication() {
		return Authentication.builder()
				.user(TestUtils.TPP_USER)
				.password(TestUtils.TPP_PASSWORD)
				//.scope("certificate:manage,revoke,discover;configuration:manage")
				.build();
	}
	
	private Authentication getAuthenticationMissingUserPassword() {
		return Authentication.builder().user("").password("").build();
	}
	
	private Authentication getAuthenticationUnauthorizedUserPassword() {
		return Authentication.builder().user("user").password("password").build();
	}
	
	private Config getConfig(Authentication authentication) {
		return Config.builder()
				.connectorType(ConnectorType.TPP)
				.baseUrl(TestUtils.TPP_URL)
				.credentials(authentication)
				.build();
	}
}
