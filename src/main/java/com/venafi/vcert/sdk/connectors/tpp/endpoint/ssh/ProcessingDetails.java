package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class ProcessingDetails {
	@SerializedName("Status")
	private String status;
	@SerializedName("StatusDescription")
	private String statusDescription;
}