package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.certificate.SshCertificateDetails;

import lombok.Data;

@Data
public class TppSshCertRetrieveResponse {
	@SerializedName("ProcessingDetails")
	private ProcessingDetails processingDetails;
	@SerializedName("Guid")
	private String guid;
	@SerializedName("DN")
	private String dn;
	@SerializedName("CertificateData")
	private String certificateData;
	@SerializedName("PrivateKeyData")
	private String privateKeyData;
	@SerializedName("PublicKeyData")
	private String publicKeyData;
	@SerializedName("CAGuid")
	private String caGuid;
	@SerializedName("")
	private String cadn;
	@SerializedName("CertificateDetails")
	private SshCertificateDetails certificateDetails;
	@SerializedName("Response")
	private TppSshCertResponseInfo response;
}