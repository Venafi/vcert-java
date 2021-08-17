package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class TppSshCertResponseInfo {
	@SerializedName("ErrorCode")
	private int errorCode;
	@SerializedName("ErrorMessage")
	private String errorMessage;
	@SerializedName("Success")
	private boolean success;
}