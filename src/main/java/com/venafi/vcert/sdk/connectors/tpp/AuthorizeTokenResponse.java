package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class AuthorizeTokenResponse extends TokenResponse {

	@SerializedName("identity")
	private String  identity;
}
