package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;

public interface Connector {

//    ConnectorType getType();
//    void setBaseUrl(String url) throws VCertException;
//    void setZone(String zone);
//    void ping() throws VCertException;
    void register(String eMail) throws VCertException;
    void authenticate(Authentication auth) throws VCertException;
    ZoneConfiguration readZoneConfiguration(String zone) throws VCertException;
//    CertificateRequest generateRequest(ZoneConfiguration config) throws VCertException;
//    String generateRequest(CertificateRequest request, String zone) throws VCertException;
//    Collection retrieveCertificate(CertificateRequest request) throws VCertException;
//    void revokeCertificate(RevocationRequest request) throws VCertException;
//    String renewCertificate(RenewalRequest request) throws VCertException;
//    ImportResponse importCertificate(ImportRequest request) throws VCertException;
//    Policy readPolicyConfiguration(String zone) throws VCertException;


}
