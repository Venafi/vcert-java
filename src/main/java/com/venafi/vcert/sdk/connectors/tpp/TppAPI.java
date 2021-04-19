package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import feign.Response;

public abstract class TppAPI {

    protected Tpp tpp;

    public TppAPI(Tpp tpp) {
        this.tpp = tpp;
    }

    abstract String getAuthKey() throws VCertException;
    abstract DNIsValidResponse dnIsValid(DNIsValidRequest request) throws VCertException;//, String authKey);
    abstract CreateDNResponse createDN(CreateDNRequest request) throws VCertException;//, String authKey);
    abstract SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request) throws VCertException;//, String authKey);
    abstract GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request) throws VCertException;//, String authKey);
    abstract GetPolicyResponse getPolicy(GetPolicyRequest request) throws VCertException;//, String authKey);
    abstract Response clearPolicyAttribute(ClearPolicyAttributeRequest request) throws VCertException;
}
