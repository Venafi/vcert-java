package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public abstract class AbstractTPPConnector {
    protected static final Pattern policy = Pattern.compile("^\\\\VED\\\\Policy");
    protected static final String HEADER_API_KEY = "x-venafi-api-key";
    protected static final String HEADER_AUTHORIZATION = "Authorization";
    protected static final String HEADER_VALUE_AUTHORIZATION = "Bearer %s";

    protected final Tpp tpp;

    @Getter
    protected String zone;
    @Getter
    protected String vendorAndProductName;
    protected static final String tppAttributeManagementType = "Management Type";
    protected static final String tppAttributeManualCSR = "Manual Csr";

    // TODO can be enum
    @SuppressWarnings("serial")
    protected static Map<String, Integer> revocationReasons = new HashMap<String, Integer>() {
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

    public AbstractTPPConnector(Tpp tpp) {
        this.tpp = tpp;
    }

    @Data
    @AllArgsConstructor
    public static class AuthorizeRequest {
        private String username;
        private String password;
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
