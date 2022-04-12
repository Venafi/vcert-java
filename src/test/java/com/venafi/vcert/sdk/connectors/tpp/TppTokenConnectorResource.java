package com.venafi.vcert.sdk.connectors.tpp;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.endpoint.Authentication;

import lombok.Getter;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Getter
public class TppTokenConnectorResource implements BeforeEachCallback, BeforeAllCallback, AfterEachCallback {
	
	private TppTokenConnector connector;
	private TokenInfo info;

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		if(info ==  null)
			authenticate();
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		authenticate();
	}
	
	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		if(context.getTags()!=null && context.getTags().contains("InvalidAuthentication"))
			info = null;
	}
	
	private void authenticate() throws Exception {
		Authentication authentication = Authentication.builder()
				.user(TestUtils.TPP_USER)
				.password(TestUtils.TPP_PASSWORD)
				.scope("certificate:manage,revoke,discover;configuration:manage")
				.build();
		
		connector = new TppTokenConnector(TppToken.connect(TestUtils.TPP_TOKEN_URL));

		TokenInfo info = connector.getAccessToken(authentication);

		assertThat(info).isNotNull();
		assertThat(info.authorized()).isTrue();
		assertThat(info.errorMessage()).isNull();
		assertThat(info.accessToken()).isNotNull();
		assertThat(info.refreshToken()).isNotNull();

		this.info = info;
	}

}
