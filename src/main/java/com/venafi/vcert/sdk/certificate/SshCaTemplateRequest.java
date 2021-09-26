/**
 * 
 */
package com.venafi.vcert.sdk.certificate;

import lombok.Data;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
@Data
public class SshCaTemplateRequest {
	private String dn;
	private String guid;
}
