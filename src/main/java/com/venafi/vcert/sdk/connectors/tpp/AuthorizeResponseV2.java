package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class AuthorizeResponseV2 {

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

	@SerializedName("identity")
	private String  identity;

	@SerializedName("refresh_until")
	private long refreshUntil;

}
