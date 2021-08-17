package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class TppSshCertRequestResponse {
	@SerializedName("DN")
	private String dn;
	@SerializedName("Guid")
	private String guid;
	@SerializedName("Status")
	private String status;//TODO Ask why it's not being used in VCert-go implementation
	@SerializedName("Permissions")
	private String permissions;
	@SerializedName("Response")
	private TppSshCertResponseInfo response;
}