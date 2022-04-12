package com.venafi.vcert.sdk.connectors.tpp;

import java.util.Map;

import com.google.common.io.CharStreams;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.CertificateRenewalRequest;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.CertificateRequestsPayload;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.CertificateRetrieveRequest;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.CertificateRevokeRequest;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.ReadZoneConfigurationRequest;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.ReadZoneConfigurationResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRenewalResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRequestResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRetrieveResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRevokeResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateSearchResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCaTemplateRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCaTemplateResponse;
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

    BrowseIdentitiesResponse browseIdentities(BrowseIdentitiesRequest request) throws VCertException{
        return tpp.browseIdentities(request, getAuthKey());
    }

    ValidateIdentityResponse validateIdentity(ValidateIdentityRequest request) throws VCertException{
        return tpp.validateIdentity(request, getAuthKey());
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
