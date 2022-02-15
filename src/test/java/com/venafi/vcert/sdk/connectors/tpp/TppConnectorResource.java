/**
 * 
 */
package com.venafi.vcert.sdk.connectors.tpp;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.endpoint.Authentication;

import lombok.Getter;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Getter
public class TppConnectorResource implements BeforeAllCallback {
	
	private TppConnector connector;

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		authenticate();
	}
	
	private void authenticate() throws Exception {
		Authentication authentication = Authentication.builder()
				.user(TestUtils.TPP_USER)
				.password(TestUtils.TPP_PASSWORD)
				//.scope("certificate:manage,revoke,discover;configuration:manage")
				.build();
		
		connector = new TppConnector(Tpp.connect(TestUtils.TPP_URL));

		connector.authenticate(authentication);
	}

}
