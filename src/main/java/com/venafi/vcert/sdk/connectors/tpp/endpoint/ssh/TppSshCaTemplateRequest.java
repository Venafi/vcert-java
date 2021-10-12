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
public class TppSshCaTemplateRequest {
	@SerializedName("DN")
	private String dn;
	@SerializedName("Guid")
	private String guid;
}
