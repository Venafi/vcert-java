package com.venafi.vcert.sdk.connectors.tpp;

import static com.venafi.vcert.sdk.TestUtils.getTestIps;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.ConnectorException.FailedToRevokeTokenException;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

import feign.FeignException;
import feign.FeignException.BadRequest;

class TppTokenConnectorAT {
	
	@RegisterExtension
	public static final TppTokenConnectorResource connectorResource = new TppTokenConnectorResource();

	@Test
	@DisplayName("Authenticate with credentials from Config object")
	void authenticateNoParameter() throws VCertException{
		TokenInfo localInfo = connectorResource.connector().getAccessToken();

		assertThat(localInfo).isNotNull();
		assertThat(localInfo.authorized()).isTrue();
		assertThat(localInfo.errorMessage()).isNull();
		assertThat(localInfo.accessToken()).isNotNull();
		assertThat(localInfo.refreshToken()).isNotNull();
	}
	
	@Test
	@Tag("InvalidAuthentication")
	@DisplayName("Authenticate with invalid credentials")
	void authenticateInvalid() throws VCertException{
		Authentication authentication = Authentication.builder()
				.user("sample")
				.password("password")
				.scope("certificate:manage,revoke,discover")
				.build();
		
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> connectorResource.connector().getAccessToken(authentication))
	    .withRootCauseInstanceOf(BadRequest.class);

		// After setting invalid credentials to TPP, setting variable <info> to null
		// will allow for new token to be authorized
		//connectorResource.info(null);
	}

	@Test
	void readZoneConfiguration() throws VCertException {
		try {
			connectorResource.connector().readZoneConfiguration(TestUtils.TPP_ZONE);
		} catch (FeignException fe) {
			throw VCertException.fromFeignException(fe);
		}
	}

	@Test
	void readZoneConfigurationInLongFormat() throws VCertException {
		try {
			connectorResource.connector().readZoneConfiguration("\\VED\\Policy\\"+TestUtils.TPP_ZONE);
		} catch (FeignException fe) {
			throw VCertException.fromFeignException(fe);
		}
	}

	@Test
	void ping() throws VCertException {
		assertThatCode(() -> connectorResource.connector().ping()).doesNotThrowAnyException();
	}

	@Test
	void generateRequest() throws VCertException, IOException {
		String commonName = TestUtils.randomCN();
		ZoneConfiguration zoneConfiguration = connectorResource.connector().readZoneConfiguration(TestUtils.TPP_ZONE);
		CertificateRequest certificateRequest = new CertificateRequest()
				.subject(new CertificateRequest.PKIXName().commonName(commonName)
						.organization(Collections.singletonList("Venafi, Inc."))
						.organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
						.country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
						.province(Collections.singletonList("Utah")))
				.dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
				.ipAddresses(getTestIps()).keyType(KeyType.RSA).keyLength(2048);

		certificateRequest = connectorResource.connector().generateRequest(zoneConfiguration, certificateRequest);

		assertThat(certificateRequest.csr()).isNotEmpty();

		PKCS10CertificationRequest request = (PKCS10CertificationRequest) new PEMParser(
				new StringReader(new String(certificateRequest.csr()))).readObject();

		// Values overridden by policy which is why they don't match the above values
		String subject = request.getSubject().toString();

		assertThat(subject).contains(format("CN=%s", commonName));
	}

	@Test
	void readPolicyConfiguration() {
		assertThrows(UnsupportedOperationException.class,
				() -> connectorResource.connector().readPolicyConfiguration("zone"));
	}

	@Test
	void refreshToken() throws VCertException{
		TokenInfo refreshInfo = connectorResource.connector().refreshAccessToken(TestUtils.CLIENT_ID);

		assertThat(refreshInfo).isNotNull();
		assertThat(refreshInfo.authorized()).isTrue();
		assertThat(refreshInfo.errorMessage()).isNull();
		assertThat(refreshInfo.accessToken()).isNotNull();
		assertThat(refreshInfo.accessToken()).isNotEqualTo(connectorResource.info().accessToken());
		assertThat(refreshInfo.refreshToken()).isNotNull();
		assertThat(refreshInfo.refreshToken()).isNotEqualTo(connectorResource.info().refreshToken());
	}

	@Test
	@Tag("InvalidAuthentication")
	void refreshTokenInvalid() throws VCertException{
		Authentication invalidCredentials = Authentication.builder()
				//.accessToken("abcde==")
				.refreshToken("1234-1234-12345-123")
				.build();
		
		//given that only the refreshToken was provided, then no validation can be performed,
		//so the credentials are set to the Connector
		connectorResource.connector().authorize(invalidCredentials);
		
		assertThatExceptionOfType(VCertException.class)
		.isThrownBy(() -> connectorResource.connector().refreshAccessToken(TestUtils.CLIENT_ID))
	    .withRootCauseInstanceOf(BadRequest.class);

		// After setting invalid credentials to TPP, setting variable <info> to null
		// will allow for new token to be authorized
		//connectorResource.info(null);
	}

	@Test
	@Tag("InvalidAuthentication")
	void revokeToken() throws VCertException{
		int status = connectorResource.connector().revokeAccessToken();
		assertThat(status).isEqualTo(200);

		// After revoking the current token, setting variable <info> to null
		// will allow for new token to be authorized
		//connectorResource.info(null);
	}

	@Test
	@Tag("InvalidAuthentication")
	void revokeTokenInvalid() throws VCertException{
		/*Authentication invalidCredentials = Authentication.builder()
				.accessToken("abcde==")
				.refreshToken("1234-1234-12345-123")
				.build();
		
		connectorResource.connector().authorize(invalidCredentials);*/
		String accessToken = connectorResource.connector().credentials.accessToken();
		
		connectorResource.connector().credentials.accessToken("abcde==");

		assertThrows(FailedToRevokeTokenException.class, () ->connectorResource.connector().revokeAccessToken());
		// After setting invalid credentials to TPP, setting variable <info> to null
		// will allow for new token to be authorized
		//connectorResource.info(null);
		
		connectorResource.connector().credentials.accessToken(accessToken);
	}

	@Test
	@DisplayName("TPP - Testing the setPolicy() and getPolicy() methods")
	public void createAndGetPolicy() throws VCertException {

		String policyName = TppTestUtils.getRandomZone();

		PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();

		connectorResource.connector().setPolicy(policyName, policySpecification);

		PolicySpecification policySpecificationReturned = connectorResource.connector().getPolicy(policyName);

		//The returned policySpecification will have the policy's name so it will copied to the source policySpecification
		//due it doesn't contain it
		policySpecification.name(policySpecificationReturned.name());
		//setting to null, because the returned should not contains the defaults
		policySpecification.defaults(null);

		assertEquals(policySpecification, policySpecificationReturned);
	}
}
