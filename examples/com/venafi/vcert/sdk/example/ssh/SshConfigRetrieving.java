/**
 * 
 */
package com.venafi.vcert.sdk.example.ssh;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.certificate.SshCaTemplateRequest;
import com.venafi.vcert.sdk.certificate.SshConfig;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

/**
 * The following example is to show how to get the Config from a given SSH CA on TPP.
 * 
 * @author Marcos E. Albornoz Abud
 *
 */
public class SshConfigRetrieving {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
        try {
            String template = "<TPP_SSH_CA>";//replace it by the CADN or the CA Name
            String user = "<TPPUSER>";//replace it by the TPP User
            String password = "<TPPPASSWORD>";//replace it by the TPP Password
            String baseUri = "<TPP_URL>";//replace it by the TPP URL
    		
            //1. Get a VCertClient for TPP setting the scope to "ssh:manage"
            //1.a The Authentication is optional, but if that is not provided, 
            // then the principals of the returned SshConfig object will not be retrieved.
            Authentication auth = Authentication.builder()
                    .user(user)
                    .password(password)
                    .scope("ssh:manage")
                    .build();


            Config config = Config.builder()
                    .connectorType(ConnectorType.TPP_TOKEN)
                    .baseUrl(baseUri)
                    .build();

            VCertTknClient client = new VCertTknClient(config);
            client.getAccessToken(auth);
            
            //2. Get an instance of com.venafi.vcert.sdk.certificate.SshCaTemplateRequest class.
    		SshCaTemplateRequest req = new SshCaTemplateRequest()
    				.template(template);

            //3. Use the VCertClient method retrieveSshConfig() to retrieve the Config of the given 
    		// SSH CA on TPP.
    		//3.a Remember that Authentication is optional, but if that is not provided, 
            // then the principals attribute of the returned SshConfig object will not be retrieved.
    		SshConfig sshConfig = client.retrieveSshConfig(req);
    		
            client.revokeAccessToken();

        } catch ( Exception e) {
            e.printStackTrace();
        }

	}

}
