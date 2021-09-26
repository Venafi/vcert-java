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
public class SshConfig {
	
	private String caPublicKey;
	private String[] principals;
}
