package com.venafi.vcert.sdk.connectors.cloud;

import com.google.common.io.CharStreams;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.Is;
import feign.Response;
import lombok.Data;
import lombok.Getter;

import java.io.IOException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.time.Duration.ZERO;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

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
        Response response = doPing();
        if(response.status() != 200) {
            throw new VCertException(format("Unexpected status code on Venafi Cloud ping. Status: %d %s", response.status(), response.reason()));
        }
    }

    private Response doPing() {
        return cloud.ping(auth.apiKey());
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
                if(request.csr().length == 0) {
                    throw new VCertException("CSR was supposed to be provided by user, but it's empty");
                }
                break;
            case ServiceGeneratedCSR:
                request.csr(null);
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
                        .zoneId(z.id())
                        .csr(new String(request.csr())));
        String requestId = response.certificateRequests().get(0).id();
        request.pickupId(requestId);
        return requestId;
    }

    @Override
    public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
        if(request.fetchPrivateKey()) {
            throw new VCertException("Failed to retrieve private key from Venafi Cloud service: not supported");
        }
        String certId = "";
        if(isBlank(request.pickupId()) && isNotBlank(request.thumbprint())) {
            String certificateRequestId = null;
            Cloud.CertificateSearchResponse certificateSearchResponse = searchCertificatesByFingerprint(request.thumbprint());
            if(certificateSearchResponse.certificates().size() == 0) {
                throw new VCertException(format("No certifiate found using fingerprint %s", request.thumbprint()));
            }

            List<String> reqIds = new ArrayList<>();
            boolean isOnlyOneCertificateRequestId = true;
            for(Cloud.Certificate certificate : certificateSearchResponse.certificates()) {
                reqIds.add(certificate.certificateRequestId());
                if(isNotBlank(certificateRequestId) && certificateRequestId.equals(certificate.certificateRequestId())) {
                    isOnlyOneCertificateRequestId = true;
                }
                if(isNotBlank(certificate.certificateRequestId())) {
                    certificateRequestId = certificate.certificateRequestId();
                } else {
                    certId = certificate.id();
                }
            }
            if(!isOnlyOneCertificateRequestId) {
                throw new VCertException(format("More than one CertificateRequestId was found with the same Fingerprint: %s", reqIds));
            }
            request.pickupId(certificateRequestId);
        }

        // TODO move this retry logic to feign client
        Instant startTime = Instant.now();
        while(true) {
            if(isBlank(request.pickupId())) {
                break;
            }

            CertificateStatus certificateStatus = getCertificateStatus(request.pickupId());
            if("ISSUED".equals(certificateStatus.status())) {
                break;
            } else if("FAILED".equals(certificateStatus.status())) {
                throw new VCertException(format("Failed to retrieve certificate. Status: %s", certificateStatus.toString()));
            }

            // Status either REQUESTED or PENDING
            if(ZERO.equals(request.timeout())) {
                throw new VCertException(format("Failed to retrieve certificate %s. Status %s", request.pickupId(), certificateStatus.status()));
            }

            if(Instant.now().isAfter(startTime.plus(request.timeout()))) {
                throw new VCertException(format("Timeout trying to retrieve certificate %s", request.pickupId()));
            }

            try {
                TimeUnit.SECONDS.sleep(2);
            } catch(InterruptedException e) {
                e.printStackTrace();
                throw new VCertException("Error attempting to retry", e);
            }
        }

        if(user == null || user.company() == null) {
            throw new VCertException("Must be autheticated to retieve certificate");
        }

        if(isNotBlank(request.pickupId())) {

            // Todo cleanup unnecessary switch
            String chainOption;
            switch(request.chainOption()) {
                case ChainOptionRootFirst:
                    chainOption = "ROOT_FIRST";
                    break;
                case ChainOptionRootLast:
                case ChainOptionIgnore:
                default:
                    chainOption = "EE_FIRST";
                    break;
            }
            String body = certificateViaCSR(request.pickupId(), chainOption);
            PEMCollection pemCollection = PEMCollection.fromResponse(body, request.chainOption());
            request.checkCertificate(pemCollection.certificate());
            return pemCollection;
        } else {
            String body = certificateAsPem(certId);
            return PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore);
        }
    }

    private String certificateViaCSR(String requestId, String chainOrder) throws VCertException {
        // We should decode this as is not REST, multiple decoders should be supported
        // by feign as a potential improvement.
        Response response = cloud.certificateViaCSR(requestId, auth.apiKey(), chainOrder);
        if (response.status() != 200) {
            throw new VCertException(String.format("Invalid response fetching the certificate via CSR: %s",
                    response.reason()));
        }
        try {
            return CharStreams.toString(response.body().asReader());
        }catch (IOException e) {
            throw new VCertException("Unable to read the PEM certificate");
        }

    }

    private String certificateAsPem(String requestId) {
        return cloud.certificateAsPem(requestId, auth.apiKey());
    }

    private CertificateStatus getCertificateStatus(String requestId) {
        return cloud.certificateStatus(requestId, auth.apiKey());
    }

    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        throw new UnsupportedOperationException("not supported by endpoint");
    }

    @Override
    public String renewCertificate(RenewalRequest request) throws VCertException {

        String certificateRequestId = null;

        if (!Is.blank(request.thumbprint())) {
            Cloud.CertificateSearchResponse result = this.searchCertificatesByFingerprint(request.thumbprint());
            Set<String> requestIds = result.certificates()
                    .stream()
                    .map(c -> c.certificateRequestId())
                    .collect(Collectors.toSet());

            if (requestIds.size() > 1) {
                throw new VCertException(
                        String.format("More than one CertificateRequestId was found with the same Fingerprint: %s",
                                request.thumbprint()));

            } else if (requestIds.size() == 0) {
                throw new VCertException(String.format("Cloud service can not find a certificate with Fingerprint: %s",
                        request.thumbprint()));
            }

        certificateRequestId = requestIds.iterator().next();

        } else if (!Is.blank(request.certificateDN())) {
            certificateRequestId = request.certificateDN();
        } else {
            throw new VCertException("failed to create renewal request: CertificateDN or Thumbprint required");
        }


        final CertificateStatus status = cloud.certificateStatus(certificateRequestId, auth.apiKey());
        VCertException.throwIfNull(status.managedCertificateId(),
                        String.format("failed to submit renewal request for certificate: ManagedCertificateId is empty, certificate status is %s", status.status()));
        VCertException.throwIfNull(status.zoneId(),
                String.format("failed to submit renewal request for certificate: ZoneId is empty, certificate status is %s", status.status()));


        ManagedCertificate managedCertificate = cloud.managedCertificate(status.managedCertificateId(), auth.apiKey());
        if (!managedCertificate.latestCertificateRequestId().equals(certificateRequestId)) {
            final StringBuilder errorStr = new StringBuilder();
            errorStr.append("Certificate under requestId %s ");
            errorStr.append(!Is.blank(request.thumbprint())? String.format("with thumbprint %s ", request.thumbprint()):"");
            errorStr.append("is not the latest under ManagedCertificateId %s. The latest request is %s. ");
            errorStr.append("This error may happen when revoked certificate is requested to be renewed.");

            throw new VCertException(String.format(errorStr.toString(), certificateRequestId, managedCertificate.id(),
                    managedCertificate.latestCertificateRequestId()));
        }

        final CertificateRequestsPayload certificateRequest = new CertificateRequestsPayload();
        certificateRequest.zoneId(status.zoneId());
        certificateRequest.existingManagedCertificateId(managedCertificate.id());

        certificateRequest.reuseCSR(Objects.nonNull(request.request()) && request.request().csr().length > 0);
        if (certificateRequest.reuseCSR) {
            certificateRequest.csr(Arrays.toString(request.request().csr()));
        }

        CertificateRequestsResponse response = cloud.certificateRequest(auth.apiKey(), certificateRequest);
        return response.certificateRequests().get(0).id();
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
            switch(certificatePolicy.certificatePolicyType()) {
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
        private String zoneId;
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
