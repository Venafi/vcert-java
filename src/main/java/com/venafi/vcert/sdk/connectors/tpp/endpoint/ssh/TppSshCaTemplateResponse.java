/**
 * 
 */
package com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Data
public class TppSshCaTemplateResponse {
	
	@SerializedName("AccessControl")
	private AccessControl accessControl;
	
	@SerializedName("Response")
	private TppSshCertResponseInfo response;
	
	@Data
	public static class AccessControl {
		@SerializedName("DefaultPrincipals")
		private String[] defaultPrincipals;
	}
}
