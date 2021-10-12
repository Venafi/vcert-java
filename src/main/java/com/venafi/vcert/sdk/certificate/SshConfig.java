/**
 * 
 */
package com.venafi.vcert.sdk.certificate;

import lombok.Data;

/**
 * This class contains info related to the configuration of the related SSH CA.
 * <br><br>
 * For more information you can see 
 * {@link com.venafi.vcert.sdk.VCertClient#retrieveSshConfig(SshCaTemplateRequest) VCertClient.retrieveSshConfig(SshCaTemplateRequest)} or  
 * {@link com.venafi.vcert.sdk.VCertTknClient#retrieveSshConfig(SshCaTemplateRequest) VCertTknClient.retrieveSshConfig(SshCaTemplateRequest)}; 
 * 
 * @author Marcos E. Albornoz Abud
 */
@Data
public class SshConfig {
	
	private String caPublicKey;
	private String[] principals;
}
