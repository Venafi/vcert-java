package com.venafi.vcert.sdk.certificate;

import lombok.Data;

@Data
public class SshCertRetrieveDetails {

	private String guid;
	private String dn;
	private String caGuid;
	private String cadn;
	private String certificateData;
	private String privateKeyData;
	private String publicKeyData;
	private SshCertificateDetails certificateDetails;
}
