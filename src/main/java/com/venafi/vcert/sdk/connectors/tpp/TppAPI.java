package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.io.CharStreams;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.*;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.*;
import feign.Response;

import java.util.Map;

public abstract class TppAPI {

    protected Tpp tpp;

    public TppAPI(Tpp tpp) {
        this.tpp = tpp;
    }

    abstract String getAuthKey() throws VCertException;

    Response ping() throws VCertException {
        return tpp.ping(getAuthKey());
    }

    ReadZoneConfigurationResponse readZoneConfiguration(ReadZoneConfigurationRequest request) throws VCertException {
        return tpp.readZoneConfiguration(request, getAuthKey());
    }

    CertificateRequestResponse requestCertificate(CertificateRequestsPayload payload) throws VCertException {
        return tpp.requestCertificate(payload, getAuthKey());
    }

    CertificateRetrieveResponse certificateRetrieve(CertificateRetrieveRequest request)throws VCertException {
        return tpp.certificateRetrieve(request, getAuthKey());
    }

    CertificateSearchResponse searchCertificates(Map<String, String> searchRequest) throws VCertException {
        return tpp.searchCertificates(searchRequest, getAuthKey());
    }

    CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) throws VCertException {
        return tpp.revokeCertificate(request, getAuthKey());
    }

    CertificateRenewalResponse renewCertificate(CertificateRenewalRequest request) throws VCertException {
        return tpp.renewCertificate(request, getAuthKey());
    }

    ImportResponse importCertificate(ImportRequest request) throws VCertException {
        return tpp.importCertificate(request, getAuthKey());
    }

    public DNIsValidResponse dnIsValid(DNIsValidRequest request) throws VCertException {
        return tpp.dnIsValid(request, getAuthKey());
    }

    CreateDNResponse createDN(CreateDNRequest request) throws VCertException {
        return tpp.createDN(request, getAuthKey());
    }

    SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request) throws VCertException {
        return tpp.setPolicyAttribute(request, getAuthKey());
    }

    GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request) throws VCertException {
        return tpp.getPolicyAttribute(request, getAuthKey());
    }

    GetPolicyResponse getPolicy(GetPolicyRequest request) throws VCertException {
        return tpp.getPolicy(request, getAuthKey());
    }

    Response clearPolicyAttribute(ClearPolicyAttributeRequest request) throws VCertException {
        return tpp.clearPolicyAttribute(request, getAuthKey());
    }

    BrowseIdentityResponse getIdentity(IdentityRequest request) throws VCertException{
        return tpp.getIdentity(request, getAuthKey());
    }

    TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request) throws VCertException {
        return tpp.requestSshCertificate(request, getAuthKey());
    }

    TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request) throws VCertException {
        return tpp.retrieveSshCertificate(request, getAuthKey());
    }

    String retrieveSshCAPublicKeyData(Map<String, String> params) throws VCertException {
        String publicKeyData;

        try {
            publicKeyData = CharStreams.toString(tpp.retrieveSshCAPublicKeyData(params).body().asReader());
        } catch (Exception e) {
            throw new VCertException(e);
        }

        return publicKeyData;
    }

    TppSshCaTemplateResponse retrieveSshCATemplate(TppSshCaTemplateRequest request) throws VCertException {
        return tpp.retrieveSshCATemplate(request, getAuthKey());
    }
}
