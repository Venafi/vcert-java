package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import java.util.Map;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class TppSshCertRequest {
	@SerializedName("CADN")
	private String cadn;
	@SerializedName("PolicyDN")
	private String policyDN;
	@SerializedName("ObjectName")
	private String objectName;
	@SerializedName("DestinationAddresses")
	private String[] destinationAddresses;
	@SerializedName("KeyId")
	private String keyId;
	@SerializedName("Principals")
	private String[] principals;
	@SerializedName("ValidityPeriod")
	private String validityPeriod;
	@SerializedName("PublicKeyData")
	private String publicKeyData;
	@SerializedName("Extensions")
	private Map<String, String> extensions;
	@SerializedName("ForceCommand")
	private String forceCommand;
	@SerializedName("SourceAddresses")
	private String[] sourceAddresses;
}