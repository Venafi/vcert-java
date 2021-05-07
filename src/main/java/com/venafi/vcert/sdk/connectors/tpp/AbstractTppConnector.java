package com.venafi.vcert.sdk.connectors.tpp;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.ServerPolicy;

import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

public abstract class AbstractTppConnector {
    protected static final Pattern POLICY_REGEX = Pattern.compile("^\\\\VED\\\\Policy");
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
        Matcher candidate = POLICY_REGEX.matcher(zone);
        if (!candidate.matches()) {
            if (!POLICY_REGEX.matcher(zone).matches()) {
                result = "\\" + result;
            }
            result = "\\VED\\Policy" + result;
        }
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
                throw new VCertException("The policy's parent doesn't exist");

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
