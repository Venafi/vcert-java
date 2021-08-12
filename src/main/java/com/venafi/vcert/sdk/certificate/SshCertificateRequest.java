package com.venafi.vcert.sdk.certificate;

import static java.time.temporal.ChronoUnit.MINUTES;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import lombok.Data;

@Data
public class SshCertificateRequest {
	
	private String cadn;
	private String policyDN;
	private String objectName;
	private String[] destinationAddresses;
	private String keyId;
	private String[] principals;
	private String validityPeriod;
	private String publicKeyData;
	private Map<String, String> extensions;
	private String forceCommand;
	private String[] sourceAddresses;

	private String pickupID;
	private String guid;
	//private boolean includePrivateKeyData;
	private String privateKeyPassphrase;
	//private String privateKeyFormat;
	//private boolean includeCertificateDetails;
	
	private Duration timeout;
	
	public Duration timeout() {
		return (!Objects.isNull(timeout)) ? timeout : Duration.of(5, MINUTES);
	}
}
