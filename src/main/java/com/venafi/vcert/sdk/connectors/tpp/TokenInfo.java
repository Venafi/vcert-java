package com.venafi.vcert.sdk.connectors.tpp;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenInfo {

	private String accessToken;
	private String refreshToken;
	private long  expires;
	private String  tokenType;
	private String  scope;
	private String  identity;
	private long refreshUntil;
	private boolean authorized;
	private String errorMessage;
}
