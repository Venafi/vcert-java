package com.venafi.vcert.sdk.connectors.tpp;

import static java.time.Duration.ZERO;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ConnectorException.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequestResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveResponse;
import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

public abstract class AbstractTppConnector {
    protected static final String HEADER_VALUE_AUTHORIZATION = "Bearer %s";

    protected static final String FAILED_TO_AUTHENTICATE_MESSAGE = "failed to authenticate: ";
    protected static final String MISSING_CREDENTIALS_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing credentials";
    protected static final String MISSING_REFRESH_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing refresh token";
    protected static final String MISSING_ACCESS_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing access token";
    protected static final String TPP_ATTRIBUTE_MANAGEMENT_TYPE = "Management Type";
    protected static final String TPP_ATTRIBUTE_MANUAL_CSR = "Manual Csr";

    // TODO can be enum
    @SuppressWarnings("serial")
    protected static final Map<String, Integer> revocationReasons = new HashMap<String, Integer>() {
        {
            put("", 0); // NoReason
            put("none", 0); //
            put("key-compromise", 1); // UserKeyCompromised
            put("ca-compromise", 2); // CAKeyCompromised
            put("affiliation-changed", 3); // UserChangedAffiliation
            put("superseded", 4); // CertificateSuperseded
            put("cessation-of-operation", 5); // OriginalUseNoLongerValid
        }
    };

    protected final Tpp tpp;

    @Getter
    protected String zone;
    protected String vendorAndProductName;

    protected TppAPI tppAPI;

    public AbstractTppConnector(Tpp tpp) {

        this.tpp = tpp;
        this.tppAPI = getTppAPI();
    }

    protected abstract TppAPI getTppAPI();

    @VisibleForTesting
    String getPolicyDN(final String zone) {
        String result = zone;
        
        result = result.startsWith("\\") ? result : "\\"+result;//Ensuring that the zone starts with a "\"
        result = result.startsWith("\\VED\\Policy") ? result : "\\VED\\Policy"+result; //Ensuring that the zone starts with "\VED\Policy"
        
        return result;
    }

    public void setPolicy(String policyName, TPPPolicy tppPolicy) throws VCertException {

        //ensuring that the policy name starts with the tpp_root_path
        if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
            policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

        tppPolicy.policyName( policyName );

        //if the policy doesn't exist
        if(!TppConnectorUtils.dnExist(policyName, tppAPI)){

            //verifying that the policy's parent exists
            String parentName = tppPolicy.getParentName();
            if(!parentName.equals(TppPolicyConstants.TPP_ROOT_PATH) && !TppConnectorUtils.dnExist(parentName, tppAPI))
                throw new VCertException(String.format("The policy's parent %s doesn't exist", parentName));

            //creating the policy
            TppConnectorUtils.createPolicy( policyName, tppAPI );
        } else
            TppConnectorUtils.resetAttributes(policyName, tppAPI);

        //creating policy's attributes.
        TppConnectorUtils.setPolicyAttributes(tppPolicy, tppAPI);
    }

    public TPPPolicy getTPPPolicy(String policyName) throws VCertException {

        TPPPolicy tppPolicy = new TPPPolicy();

        //ensuring that the policy name starts with the tpp_root_path
        if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
            policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

        tppPolicy.policyName( policyName );

        //populating the tppPolicy
        TppConnectorUtils.populatePolicy(tppPolicy, tppAPI);

        return tppPolicy;
    }
    
    protected TppSshCertRetrieveRequest convertToTppSshCertRetReq(SshCertificateRequest sshCertificateRequest) throws VCertException {
    	TppSshCertRetrieveRequest tppSshCertRetrieveRequest = new TppSshCertRetrieveRequest();
    	
    	tppSshCertRetrieveRequest.dn( sshCertificateRequest.pickupID() != null && !sshCertificateRequest.pickupID().equals("") ? sshCertificateRequest.pickupID() : null );
    	tppSshCertRetrieveRequest.guid( sshCertificateRequest.guid() != null && !sshCertificateRequest.guid().equals("") ? sshCertificateRequest.guid() : null );
    	tppSshCertRetrieveRequest.privateKeyPassphrase( sshCertificateRequest.privateKeyPassphrase() != null && !sshCertificateRequest.privateKeyPassphrase().equals("") ? sshCertificateRequest.privateKeyPassphrase() : null );
    	
		return tppSshCertRetrieveRequest;
	}
    
    protected SshCertRetrieveDetails convertToTppSshCertReq(TppSshCertRetrieveResponse tppSshCertRetrieveResponse) throws VCertException {
    	SshCertRetrieveDetails sshCertRetrieveDetails = new SshCertRetrieveDetails();

    	sshCertRetrieveDetails.certificateDetails( tppSshCertRetrieveResponse.certificateDetails() );
    	sshCertRetrieveDetails.privateKeyData( tppSshCertRetrieveResponse.privateKeyData() );
    	sshCertRetrieveDetails.publicKeyData( tppSshCertRetrieveResponse.publicKeyData() );
    	sshCertRetrieveDetails.certificateData( tppSshCertRetrieveResponse.certificateData() );
    	sshCertRetrieveDetails.guid( tppSshCertRetrieveResponse.guid() );
    	sshCertRetrieveDetails.dn( tppSshCertRetrieveResponse.dn() );
    	sshCertRetrieveDetails.caGuid( tppSshCertRetrieveResponse.caGuid() );
    	sshCertRetrieveDetails.cadn( tppSshCertRetrieveResponse.cadn() );

    	return sshCertRetrieveDetails;
	}
    
    protected TppSshCertRequestResponse requestTppSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException {
    	
    	TppSshCertRequest tppSshCertRequest = TppConnectorUtils.convertToTppSshCertReq(sshCertificateRequest);
    	
    	return TppConnectorUtils.requestTppSshCertificate(tppSshCertRequest, tppAPI);
    }
    
    protected SshCertRetrieveDetails retrieveTppSshCertificate(SshCertificateRequest sshCertificateRequest) 
			throws VCertException {
		
		TppSshCertRetrieveResponse tppSshCertRetrieveResponse = null;
		
		TppSshCertRetrieveRequest tppSshCertRetrieveRequest = TppConnectorUtils.convertToTppSshCertRetReq(sshCertificateRequest);
		
		// TODO move this retry logic to feign client
        Instant startTime = Instant.now();
        while (true) {
        	tppSshCertRetrieveResponse = retrieveTppSshCertificate(tppSshCertRetrieveRequest);
        	
        	//if the certificate was returned(Issued)
        	if( StringUtils.isNotBlank(tppSshCertRetrieveResponse.certificateData())) {
        		break;
        	}
        	
        	//if the certificate request was rejected
        	if( tppSshCertRetrieveResponse.response().success() && tppSshCertRetrieveResponse.status().equals("Rejected") )
        		throw new CertificateRejectedException(sshCertificateRequest.pickupID());

        	//if the certificate is pending to be issued
            if (ZERO.equals(sshCertificateRequest.timeout())) {
                throw new CertificatePendingException(sshCertificateRequest.pickupID());
            }
            
            //if the timeout was reached
            if (Instant.now().isAfter(startTime.plus(sshCertificateRequest.timeout()))) {
                throw new RetrieveCertificateTimeoutException(sshCertificateRequest.pickupID());
            }

            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new AttemptToRetryException(e);
            }
        }
        
        return TppConnectorUtils.convertToSshCertRetrieveDetails(tppSshCertRetrieveResponse);
	}
    
    private TppSshCertRetrieveResponse retrieveTppSshCertificate(TppSshCertRetrieveRequest request) throws VCertException {
    	return getTppAPI().retrieveSshCertificate(request);
    }

    @Data
    @AllArgsConstructor
    public static class AuthorizeRequest {
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class AuthorizeTokenRequest{

        @SerializedName("username")
        private String username;

        @SerializedName("password")
        private String password;

        @SerializedName("client_id")
        private String clientId;

        @SerializedName("scope")
        private String scope;

        @SerializedName("state")
        private String state;

        @SerializedName("redirect_uri")
        private String redirectUri;

    }

    @Data
    @AllArgsConstructor
    static class RefreshTokenRequest{
        @SerializedName("refresh_token")
        private String refreshToken;
        @SerializedName("client_id")
        private String clientId;
    }

    @Data
    @AllArgsConstructor
    public static class ReadZoneConfigurationRequest {
        String policyDN;
    }

    @Data
    public static class ReadZoneConfigurationResponse {
        Object error;
        ServerPolicy policy;
    }

    @Data
    public static class CertificateRequestsPayload {
        @SerializedName("PolicyDN")
        private String policyDN;
        @SerializedName("CADN")
        private String cadn;
        private String objectName;
        private String subject;
        private String organizationalUnit;
        private String organization;
        private String city;
        private String state;
        private String country;
        @SerializedName("SubjectAltNames")
        private Collection<SANItem> subjectAltNames;
        private String contact;
        @SerializedName("CASpecificAttributes")
        private Collection<NameValuePair<String, String>> caSpecificAttributes;
        @SerializedName("PKCS10")
        private String pkcs10;
        private String keyAlgorithm;
        private int keyBitSize;
        private String ellipticCurve;
        private boolean disableAutomaticRenewal;
        private String origin;
        
        @SerializedName("CustomFields")
        private ArrayList<CustomFieldRequest> customFields;
    }

    @Data
    protected static class SANItem {
        private int type;
        private String name;
    }

    @Data
    @AllArgsConstructor
    public static class NameValuePair<K, V> {
        private K name;
        private V value;
    }

    @Data
    public class CertificateRetrieveRequest {
        private String certificateDN;
        private String format;
        private String password;
        private boolean includePrivateKey;
        private boolean includeChain;
        private String friendlyName;
        private boolean rootFirstOrder;
    }

    @Data
    public class CertificateRevokeRequest {
        private String certificateDN;
        private String thumbprint;
        private Integer reason;
        private String comments;
        private boolean disable;
    }

    @Data
    public class CertificateRenewalRequest {
        private String certificateDN;
        private String PKCS10;
    }
}
