/**
 * 
 */
package com.venafi.vcert.sdk.example.ssh;

import com.sshtools.common.publickey.SshKeyPairGenerator;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshKeyPair;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

/**
 * The following example is to show how to use the SSH Certificate feature
 * in order to create and retrieve a SSH Certificate from TPP passing a KeyPair
 *  generated locally.
 *  
 * @author Marcos E. Albornoz Abud
 *
 */
public class SshCertificateRequestRetrieveWithKeyPairProvided {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
        try {
        	String keyId = "<KEY_ID>";//replace it by the key id value
        	String template = "<TPP_SSH_CA>";//replace it by the CADN or the CA Name
            String user = "<TPPUSER>";//replace it by the TPP User
            String password = "<TPPPASSWORD>";//replace it by the TPP Password
            String baseUri = "<TPP_URL>";//replace it by the TPP URL
    		
            //1. Get a VCertClient for TPP setting the scope to "ssh:manage"
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
            
            // To work with the SSH KeyPair, we are going to use some utilities from 
            // maverick-synergy project. For more information, please visit https://github.com/sshtools/maverick-synergy
            
            //2. Get an SSH Key Pair with a key size of 3072 bits
    		SshKeyPair pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.SSH2_RSA, 3072);

    		//3. Extract the Public Key and adding the KeyId as comment, at the end of the Public Key
    		//because TPP returns the Public Key on that way
    		String publicKeyData = SshKeyUtils.getFormattedKey(pair.getPublicKey(), keyId);
            
            //4. Get an instance of com.venafi.vcert.sdk.certificate.SshCertificateRequest class.
            //That can be done using the builder provided by the SshCertificateRequest
    		SshCertificateRequest req = new SshCertificateRequest()
    				.keyId(keyId)
    				.validityPeriod("4h")// if you omit it, then the validity period of the CIT will be used
    				.publicKeyData(publicKeyData)
    				.template(template);
    				//.sourceAddresses(new String[]{"test.com"});

            //5. Use the VCertClient method requestSshCertificate() to request the creation of a new 
            // SSH Certificate on TPP. This will return the DN of the created SSH Certificate which 
            // will be used to retrieve the created SSH Certificate.
    		String pickUpID = client.requestSshCertificate(req);
    		
    		//4. Set the pickUp ID to the SshCertificateRequest created. You can create a new one
    		// but in order to avoid the boilerplate, it's preferable to use the already one created.
    		req.pickupID(pickUpID);
    		
            //5. Use the VCertClient method retrieveSshCertificate() to retrieve the created
    		// SSH Certificate on TPP. It will return an instance of SshCertRetrieveDetails which 
    		// will contain the Ssh Certificate Data, the Public Key, etc.
    		SshCertRetrieveDetails sshCertRetrieveDetails  = client.retrieveSshCertificate(req);
    		
            client.revokeAccessToken();

        } catch ( Exception e) {
            e.printStackTrace();
        }
    }

}
