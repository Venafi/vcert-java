package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequestResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveResponse;

import feign.Response;

public abstract class TppAPI {

    protected Tpp tpp;

    public TppAPI(Tpp tpp) {
        this.tpp = tpp;
    }

    abstract String getAuthKey() throws VCertException;
    abstract DNIsValidResponse dnIsValid(DNIsValidRequest request) throws VCertException;
    abstract CreateDNResponse createDN(CreateDNRequest request) throws VCertException;
    abstract SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request) throws VCertException;
    abstract GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request) throws VCertException;
    abstract GetPolicyResponse getPolicy(GetPolicyRequest request) throws VCertException;
    abstract Response clearPolicyAttribute(ClearPolicyAttributeRequest request) throws VCertException;
    abstract TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request) throws VCertException;
    abstract TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request) throws VCertException;
}
