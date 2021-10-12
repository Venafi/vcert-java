/**
 * 
 */
package com.venafi.vcert.sdk.certificate;

import lombok.Data;

/**
 * This class represents the request Object to "retrieve" the {@link SshConfig} of the SSH CA specified 
 * using the {@link #template} or {@link #guid} attribute. You need to provide one of both.
 * <br><br>
 * For more information related to "retrieve SSHConfig for a given CA", see 
 * {@link com.venafi.vcert.sdk.VCertClient#retrieveSshConfig(SshCaTemplateRequest) VCertClient.retrieveSshConfig(SshCaTemplateRequest)} or  
 * {@link com.venafi.vcert.sdk.VCertTknClient#retrieveSshConfig(SshCaTemplateRequest) VCertTknClient.retrieveSshConfig(SshCaTemplateRequest)}; 
 * 
 * @author Marcos E. Albornoz Abud
 */
@Data
public class SshCaTemplateRequest {
	/**
	 * <br> The CADN or the CA name. If this is not set, then the {@link #guid} needs to be set.
	 */
	private String template;
	/**
	 * <br> A value that uniquely identifies the CA. If this is not set, then the {@link #template} needs to be set
	 */
	private String guid;
}
