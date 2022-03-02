package com.venafi.vcert.sdk.connectors.tpp;

import java.util.Map;

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
    abstract Response ping() throws VCertException;
    abstract ReadZoneConfigurationResponse readZoneConfiguration(ReadZoneConfigurationRequest request) throws VCertException;
    abstract CertificateRequestResponse requestCertificate(CertificateRequestsPayload payload) throws VCertException;
    abstract CertificateRetrieveResponse certificateRetrieve(CertificateRetrieveRequest request) throws VCertException;
    abstract CertificateSearchResponse searchCertificates(Map<String, String> searchRequest) throws VCertException;
    abstract CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) throws VCertException;
    abstract CertificateRenewalResponse renewCertificate(CertificateRenewalRequest request) throws VCertException;
    abstract ImportResponse importCertificate(ImportRequest request) throws VCertException;
    
    abstract DNIsValidResponse dnIsValid(DNIsValidRequest request) throws VCertException;
    abstract CreateDNResponse createDN(CreateDNRequest request) throws VCertException;
    abstract SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request) throws VCertException;
    abstract GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request) throws VCertException;
    abstract GetPolicyResponse getPolicy(GetPolicyRequest request) throws VCertException;
    abstract Response clearPolicyAttribute(ClearPolicyAttributeRequest request) throws VCertException;
    abstract TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request) throws VCertException;
    abstract TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request) throws VCertException;
    abstract String retrieveSshCAPublicKeyData(Map<String, String> params) throws VCertException;
    abstract TppSshCaTemplateResponse retrieveSshCATemplate(TppSshCaTemplateRequest request) throws VCertException;
}
