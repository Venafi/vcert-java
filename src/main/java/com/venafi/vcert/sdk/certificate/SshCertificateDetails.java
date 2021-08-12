package com.venafi.vcert.sdk.certificate;

import java.util.Map;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class SshCertificateDetails {
	
	@SerializedName("KeyType")
	private String keyType;
	@SerializedName("CertificateType")
	private String certificateType;
	@SerializedName("PublicKeyFingerprintSHA256")
	private String publicKeyFingerprintSHA256;
	@SerializedName("CertificateFingerprintSHA256")
	private String certificateFingerprintSHA256;
	@SerializedName("CAFingerprintSHA256")
	private String caFingerprintSHA256;
	@SerializedName("KeyID")
	private String keyID;
	@SerializedName("SerialNumber")
	private String serialNumber;
	@SerializedName("Principals")
	private String[] principals;
	@SerializedName("ValidFrom")
	private String validFrom;
	@SerializedName("ValidTo")
	private String validTo;
	@SerializedName("ForceCommand")
	private String forceCommand;
	@SerializedName("SourceAddresses")
	private String[] sourceAddresses;
	@SerializedName("Extensions")
	private Map<String, String> extensions;
	
}