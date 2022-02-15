/**
 * 
 */
package com.venafi.vcert.sdk.connectors.tpp;

import static com.venafi.vcert.sdk.TestUtils.getTestIps;

import java.net.InetAddress;
import java.util.Collections;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;

import lombok.Getter;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Getter
public class TppConnectorCertResource extends TppConnectorResource implements BeforeEachCallback {
	
	private ZoneConfiguration zoneConfiguration;
	private CertificateRequest certificateRequest;
	
	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		certificateRequest = new CertificateRequest()
				.subject(new CertificateRequest.PKIXName().commonName(TestUtils.randomCN())
						.organization(Collections.singletonList("Venafi"))
						.organizationalUnit(Collections.singletonList("Demo"))
						.country(Collections.singletonList("GB"))
						.locality(Collections.singletonList("Bracknell"))
						.province(Collections.singletonList("Berkshire")))
				.dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
				.ipAddresses(getTestIps())
				.keyType(KeyType.RSA)
				.keyLength(2048);
	}

	@Override
	public void beforeAll(ExtensionContext context) throws Exception {
		super.beforeAll(context);
		zoneConfiguration = connector().readZoneConfiguration(TestUtils.TPP_ZONE);
	}
	
}
