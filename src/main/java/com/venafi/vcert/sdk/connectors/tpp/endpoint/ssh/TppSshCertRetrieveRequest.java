package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class TppSshCertRetrieveRequest {
	@SerializedName("Guid")
	private String guid;
	@SerializedName("DN")
	private String dn;
	@SerializedName("IncludePrivateKeyData")
	private boolean includePrivateKeyData = true;
	@SerializedName("PrivateKeyPassphrase")
	private String privateKeyPassphrase;
	@SerializedName("PrivateKeyFormat")
	private String privateKeyFormat;
	@SerializedName("IncludeCertificateDetails")
	private boolean includeCertificateDetails = true;
}