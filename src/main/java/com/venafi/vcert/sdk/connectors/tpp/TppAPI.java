package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;

public abstract class TppAPI {

    protected Tpp tpp;

    public TppAPI(Tpp tpp){
        this.tpp = tpp;
    }

    abstract DNIsValidResponse dnIsValid(DNIsValidRequest request, String authKey);
    abstract CreateDNResponse createDN(CreateDNRequest request, String authKey);
    abstract SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request, String authKey);
    abstract GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request, String authKey);
    abstract GetPolicyResponse getPolicy(GetPolicyRequest request, String authKey);
}
