package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class PolicyResponse {
    @SerializedName("WhitelistedDomains")
    private String[] whitelistedDomains;
    @SerializedName("WildcardsAllowed")
    private Boolean wildcardsAllowed;
    @SerializedName("CertificateAuthority")
    private SingleValueAttribute<String> certificateAuthority;
    @SerializedName("Subject")
    private SubjectResponse subject;
    @SerializedName("KeyPair")
    private KeyPairResponse keyPair;
    @SerializedName("CsrGeneration")
    private SingleValueAttribute<String> csrGeneration;
    @SerializedName("PrivateKeyReuseAllowed")
    private Boolean privateKeyReuseAllowed;
    @SerializedName("SubjAltNameDnsAllowed")
    private Boolean subjAltNameDnsAllowed;
    @SerializedName("SubjAltNameEmailAllowed")
    private Boolean subjAltNameEmailAllowed;
    @SerializedName("SubjAltNameIpAllowed")
    private Boolean subjAltNameIpAllowed;
    @SerializedName("SubjAltNameUpnAllowed")
    private Boolean subjAltNameUpnAllowed;
    @SerializedName("SubjAltNameUriAllowed")
    private Boolean subjAltNameUriAllowed;


}
