package com.venafi.vcert.sdk.connectors.cloud;

import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.Is;
import lombok.Data;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import lombok.Getter;

import java.security.KeyStore;
import java.time.OffsetDateTime;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static java.lang.String.format;

public class CloudConnector implements Connector {

    private Cloud cloud;

    @Getter
    private UserDetails user;
    private Authentication auth;
    private String zone;

    CloudConnector(Cloud cloud) {
        this.cloud = cloud;
    }

    @Override
    public ConnectorType getType() {
        return ConnectorType.CLOUD;
    }

    @Override
    public void setBaseUrl(String url) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public void setZone(String zone) {
        this.zone = zone;
    }

    @Override
    public void ping() throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        this.auth = auth;
        this.user = cloud.authorize(auth.apiKey());
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String tag) throws VCertException {
        VCertException.throwIfNull(tag, "empty zone name");
        Zone zone = getZoneByTag(tag);
        CertificatePolicy policy = getPoliciesById(Arrays.asList(zone.defaultCertificateIdentityPolicy(), zone.defaultCertificateUsePolicy()));
        return zone.getZoneConfiguration(user, policy);
    }

    @Override
    public void register(String eMail) throws VCertException {
        this.user = cloud.register(auth.apiKey(), new UserAccount(eMail, "API"));
    }

    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request) throws VCertException {
        switch (request.csrOrigin()) {
            case LocalGeneratedCSR:
                if (config == null) {
                    config = readZoneConfiguration(zone);
                }
                config.validateCertificateRequest(request);
                config.updateCertificateRequest(request);
                request.generatePrivateKey();
                request.generateCSR();
                break;
            case UserProvidedCSR:
                break;
            case ServiceGeneratedCSR:
                break;
            default:
                throw new VCertException(format("Unreconginised request CSR origin %s", request.csrOrigin()));
        }

        return request;
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone) throws VCertException {
        if (Is.blank(zone)) {
            zone = this.zone;
        }
        if (CsrOriginOption.ServiceGeneratedCSR == request.csrOrigin()) {
            throw new VCertException("service generated CSR is not supported by Saas service");
        }
        if (user == null || user.company() == null) {
            throw new VCertException("Must be autheticated to request a certificate");
        }
        Zone z = getZoneByTag(zone);
        CertificateRequestsResponse response = cloud.certificateRequest(
                auth.apiKey(),
                new CertificateRequestsPayload()
                        .zoneID(z.id())
                        .csr(new String(request.csr())));
        String requestId = response.certificateRequests().get(0).id();
        request.pickupId(requestId);
        return requestId;
    }

    @Override
    public KeyStore retrieveCertificate(CertificateRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public String renewCertificate(RenewalRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public ImportResponse importCertificate(ImportRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public Policy readPolicyConfiguration(String zone) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    private CertificatePolicy getPoliciesById(Collection<String> ids) throws VCertException {
        CertificatePolicy policy = new CertificatePolicy();
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        for (String id : ids) {
            CertificatePolicy certificatePolicy = cloud.policyById(id, auth.apiKey());
            switch (certificatePolicy.certificatePolicyType()) {
                case "CERTIFICATE_IDENTITY": {
                    policy.subjectCNRegexes(certificatePolicy.subjectCNRegexes());
                    policy.subjectORegexes(certificatePolicy.subjectORegexes());
                    policy.subjectOURegexes(certificatePolicy.subjectOURegexes());
                    policy.subjectSTRegexes(certificatePolicy.subjectSTRegexes());
                    policy.subjectLRegexes(certificatePolicy.subjectLRegexes());
                    policy.subjectCRegexes(certificatePolicy.subjectCRegexes());
                    policy.sanRegexes(certificatePolicy.sanRegexes());
                    break;
                }
                case "CERTIFICATE_USE": {
                    policy.keyTypes(certificatePolicy.keyTypes());
                    policy.keyReuse(certificatePolicy.keyReuse());
                    break;
                }
                default:
                    throw new IllegalArgumentException(format("unknown type %s", certificatePolicy.certificatePolicyType()));
            }
        }
        return policy;
    }

    private Zone getZoneByTag(String zone) throws VCertException {
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        return cloud.zoneByTag(zone, auth.apiKey());
    }

    private Cloud.CertificateSearchResponse searchCertificates(Cloud.SearchRequest searchRequest) {
        return cloud.searchCertificates(auth.apiKey(), searchRequest);
    }

    private Cloud.CertificateSearchResponse searchCertificatesByFingerprint(String fingerprint) {
        String cleanFingerprint = fingerprint
                .replaceAll(":", "")
                .replaceAll("/.", "");

        return searchCertificates(Cloud.SearchRequest.findByFingerPrint(cleanFingerprint));
    }

    @Data
    static class CertificateRequestsPayload {
        // private String companyId;
        // private String downloadFormat;
        @SerializedName("certificateSigningRequest")
        private String csr;
        private String zoneID;
        private String existingManagedCertificateId;
        private boolean reuseCSR;
    }

    @Data
    @SuppressWarnings("WeakerAccess")
    public static class CertificateRequestsResponse {
        private List<CertificateRequestsResponseData> certificateRequests;
    }

    @Data
    static class CertificateRequestsResponseData {
        private String id;
        private String zoneId;
        private String status;
        private String subjectDN;
        private boolean generatedKey;
        private boolean defaultKeyPassword;
        private Collection<String> certificateInstanceIds;
        private OffsetDateTime creationDate;
        private String pem;
        private String der;
    }
}
