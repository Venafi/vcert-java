package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class AbstractTppConnector {
    protected static final Pattern POLICY_REGEX = Pattern.compile("^\\\\VED\\\\Policy");
    protected static final String HEADER_VALUE_AUTHORIZATION = "Bearer %s";

    protected static final String MISSING_CREDENTIALS_MESSAGE = "failed to authenticate: missing credentials";


    protected final Tpp tpp;

    @Getter
    protected String zone;
    @Getter
    protected String vendorAndProductName;
    protected static final String tppAttributeManagementType = "Management Type";
    protected static final String tppAttributeManualCSR = "Manual Csr";

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

    public AbstractTppConnector(Tpp tpp) {
        this.tpp = tpp;
    }

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
        private String client_id;

        @SerializedName("scope")
        private String scope;

        @SerializedName("state")
        private String state;

        @SerializedName("redirect_uri")
        private String redirect_uri;

    }

    @Data
    @AllArgsConstructor
    static class RefreshTokenRequest{
        @SerializedName("refresh_token")
        private String refresh_token;
        @SerializedName("client_id")
        private String client_id;
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
    }

    @Data
    protected static class SANItem {
        private int type;
        private String name;
    }

    @Data
    @AllArgsConstructor
    protected static class NameValuePair<K, V> {
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
