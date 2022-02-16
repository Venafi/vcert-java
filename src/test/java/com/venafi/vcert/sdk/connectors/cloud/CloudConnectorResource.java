/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
public class CloudConnectorResource implements BeforeEachCallback{
	
	private CloudConnector connector =  null;

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
        Cloud cloud = Cloud.connect();
        connector = new CloudConnector(cloud);
        Authentication authentication = Authentication.builder().apiKey(TestUtils.API_KEY).build();
        connector.authenticate(authentication);
	}

}
