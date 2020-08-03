package com.venafi.vcert.sdk.endpoint;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Authentication {

	private String user;
	private String password; // todo: char[] ?
	private String apiKey;
	@Builder.Default
	private String clientId = "vcert-sdk";
	@Builder.Default
	private String scope = "certificate:manage,revoke";
	@Builder.Default
	private String state = "";
	@Builder.Default
	private String redirectUri ="";

	public Authentication() {}

	public Authentication(String user, String password, String apiKey) {
		super();
		this.user = user;
		this.password = password;
		this.apiKey = apiKey;
	}

	public Authentication(String user, String password, String apiKey, String clientId, String scope, String state,
			String redirectUri) {
		super();
		this.user = user;
		this.password = password;
		this.apiKey = apiKey;
		this.clientId = clientId;
		this.scope = scope;
		this.state = state;
		this.redirectUri = redirectUri;
	}

	@Override
	public String toString() {
		return Authentication.class.getSimpleName() + "(user=" + user + ", apiKey=" + apiKey
				+ ", password=" + (!password.isEmpty() ? "****" : "not set") + ")";
	}

}