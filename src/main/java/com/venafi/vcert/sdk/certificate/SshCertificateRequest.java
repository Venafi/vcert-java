package com.venafi.vcert.sdk.certificate;

import static java.time.temporal.ChronoUnit.MINUTES;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import lombok.Data;

/*
 * This documentation is based on the documentation on https://jira.eng.venafi.com/browse/VEN-62064 and https://jira.eng.venafi.com/browse/VEN-64863
 */

/**
 * This class represents the Request Object to use to "request" a new SSH Certificate and also to "retrieve" the requested SSH Certificate.
 * <br>
 * This dual purpose is because the "request SSH Certificate" action returns the DN of the created SSH certificate
 * which will be used as the PickUp ID for the Request Object to "retrieve the generated Certificate", so in order to avoid the creation of a 
 * new Request object then the Request Object created to "Request the SSH Certificate" can be used also to "Retrieve the generated SSH Certificate" 
 * setting the PickUp ID as the value gotten in the result from the call to the "Request SSH Certificate" action.
 * <br><br>
 * For request a new SSH Certificate the attributes to use are:
 * <ul>
 * <li>{@link #cadn} <i>(Mandatory)</i>
 * <li>{@link #policyDN} <i>(Optional)</i>
 * <li>{@link #objectName} <i>(Optional)</i>
 * <li>{@link #destinationAddresses} <i>(Optional)</i>
 * <li>{@link #keyId} <i>(Mandatory)</i>
 * <li>{@link #principals} <i>(Optional)</i>
 * <li>{@link #validityPeriod} <i>(Optional)</i>
 * <li>{@link #publicKeyData} <i>(Optional)</i>
 * <li>{@link #extensions} <i>(Optional)</i>
 * <li>{@link #forceCommand} <i>(Optional)</i>
 * <li>{@link #sourceAddresses} <i>(Optional)</i>
 * </ul>
 * For retrieve a requested SSH Certificate the attributes to use are:
 * <ul>
 * <li>{@link #pickupID} <i>(Mandatory)</i>
 * <li>{@link #guid} <i>(Optional)</i>
 * <li>{@link #privateKeyPassphrase} <i>(Optional)</i>
 * </ul>
 * For more information related to the "Request SSH Certificates" action see 
 * {@link com.venafi.vcert.sdk.VCertClient#requestSshCertificate(SshCertificateRequest) VCertClient.requestSshCertificate(SshCertificateRequest)} or  
 * {@link com.venafi.vcert.sdk.VCertTknClient#requestSshCertificate(SshCertificateRequest) VCertTknClient.requestSshCertificate(SshCertificateRequest)}; 
 *  <br>and for the "Retrieve SSH Certificates" action see 
 * {@link com.venafi.vcert.sdk.VCertClient#retrieveSshCertificate(SshCertificateRequest) VCertClient.retrieveSshCertificate(SshCertificateRequest)} or  
 * {@link com.venafi.vcert.sdk.VCertTknClient#retrieveSshCertificate(SshCertificateRequest) VCertTknClient.retrieveSshCertificate(SshCertificateRequest)} 
 * 
 * @author Marcos E. Albornoz Abud
 */
@Data
public class SshCertificateRequest {
	
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Mandatory. The DN of the issuing certificate template which will be used for signing.
	 */
	private String cadn;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The DN of the policy folder where the certificate object will be created. 
	 * If this is not specified, then the policy folder specified on the certificate template will be used.
	 */
	private String policyDN;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The friendly name for the certificate object. If ObjectName is not specified, then KeyID parameter is used.
	 */
	private String objectName;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The address (FQDN/hostname/IP/CIDR) of the destination host where the certificate will be used to authenticate to. 
	 * This is applicable for client certificates and used for reporting/auditing only.
	 */
	private String[] destinationAddresses;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Mandatory. The identifier of the requested certificate (usually used to determine ownership).
	 */
	private String keyId;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The requested principals. If no value is specified, then the default principals from the certificate template will be used.
	 */
	private String[] principals;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. How much time the requester wants to have the certificate valid. The minimum is 1 second and the maximum is (at least) 20 years. 
	 * The server may override this if it is bigger than values specified on the certificate template. 
	 * The operation will not be rejected if the requested validity is bigger than the validity period set on the certificate template, 
	 * but the certificate will be valid for the value set on the template. Accepted patters are:
	 * <br>
	 * <ul>
	 * <li> Relative time s, m, h, d, and w. Example: 1w 2d 3h 4m 50s.
	 * <li> Static end day in format of yyyyMMdd or yyyyMMddHHmmss.<br> Example: 20210301
	 * </ul>
	 */
	private String validityPeriod;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The Base-64 encoded public key which will be signed (e.g. ssh-rsa AAAAB3NzaC1yc2...SA5E1F2H root@localhost.localdomain). 
	 * The comment section at the end is optional. If this is not passed, then SSH Protect will generate new keypair. 
	 * The generated private key can be retrieved with the certificate.
	 * <br><i>Note: If the Public Key is provided then it's mandatory that the KeyPair where the Public Key comes, 
	 * should be generated with a KeySize of 3072 bits.</i>
	 */
	private String publicKeyData;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The requested certificate extensions. 
	 * <br>Example: "Extensions" : {"permit-pty": "", "permit-port-forwarding": "", "login@github.com": "alice@github.com"}
	 */
	private Map<String, String> extensions;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The requested force command. Example: "ForceCommand": "/usr/scripts/db_backup.sh"
	 */
	private String forceCommand;
	/**
	 * <i>To be used to request the ssh certificate</i>.
	 * <br> Optional. The requested source addresses as list of IP/CIDR. Example: ["192.168.1.1/24", "10.0.0.1"]
	 */
	private String[] sourceAddresses;
	
	/**
	 * <i>To be used to retrieve the ssh certificate</i>.
	 * <br> Mandatory. It is the DN of the created SSH certificate object.
	 */
	private String pickupID;
	/**
	 * <i>To be used to retrieve the ssh certificate</i>.
	 * <br> Optional. A value that uniquely identifies the certificate request.
	 */
	private String guid;
	//private boolean includePrivateKeyData;
	/**
	 * <i>To be used to retrieve the ssh certificate</i>.
	 * <br> Optional. The passphrase which will be used to wrap the generated private key 
	 * before it is returned in the API response. This is applicable only in case of service-generated keypair.
	 */
	private String privateKeyPassphrase;
	//private String privateKeyFormat;
	//private boolean includeCertificateDetails;
	
	/**
	 * The time out for the request. Default 5 minutes.
	 */
	private Duration timeout;
	
	public Duration timeout() {
		return (!Objects.isNull(timeout)) ? timeout : Duration.of(5, MINUTES);
	}
}
