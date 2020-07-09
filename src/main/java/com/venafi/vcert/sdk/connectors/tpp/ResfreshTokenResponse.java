package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class ResfreshTokenResponse {

	@SerializedName("access_token")
	private String accessToken;

	@SerializedName("refresh_token")
	private String refreshToken;

	@SerializedName("expires")
	private long  expire;

	@SerializedName("token_type")
	private String  tokenType;

	@SerializedName("scope")
	private String  scope;

	@SerializedName("refresh_until")
	private long refreshUntil;
}
