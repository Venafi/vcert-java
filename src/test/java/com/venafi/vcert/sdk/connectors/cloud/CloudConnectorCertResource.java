/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.extension.ExtensionContext;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;

import lombok.Getter;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Getter
public class CloudConnectorCertResource extends CloudConnectorResource {
	
	private ZoneConfiguration zoneConfiguration;
	private CertificateRequest certificateRequest;

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		super.beforeEach(context);
		zoneConfiguration = connector().readZoneConfiguration(TestUtils.CLOUD_ZONE);
        certificateRequest = new CertificateRequest()
                .subject(new CertificateRequest.PKIXName()
                		.commonName(TestUtils.randomCN())
                        .organization(Collections.singletonList("Venafi, Inc."))
                        .organizationalUnit(Arrays.asList("DevOps", "Automated Tests"))
                        .country(Collections.singletonList("US"))
                        .locality(Collections.singletonList("Salt Lake City"))
                        .province(Collections.singletonList("Utah")))
                .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()));
	}

}
