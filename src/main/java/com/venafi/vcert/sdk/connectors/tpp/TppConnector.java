package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.Is;
import feign.Response;
import joptsimple.internal.Strings;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import java.text.MessageFormat;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static java.time.Duration.ZERO;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;


public class TppConnector implements Connector {

    private static final Pattern policy = Pattern.compile("^\\\\VED\\\\Policy");
    private static final Pattern path = Pattern.compile("^\\\\");
    private final Tpp tpp;

    @VisibleForTesting
    OffsetDateTime bestBeforeEnd;
    @Getter
    private String apiKey;

    @Getter
    private String zone;
    private static final String tppAttributeManagementType = "Management Type";
    private static final String tppAttributeManualCSR = "Manual Csr";

    // TODO can be enum
    private static Map<String, Integer> revocationReasons = new HashMap<String, Integer>() {{
        put("", 0); // NoReason
        put("none", 0); //
        put("key-compromise", 1); // UserKeyCompromised
        put("ca-compromise", 2); // CAKeyCompromised
        put("affiliation-changed", 3); // UserChangedAffiliation
        put("superseded", 4); // CertificateSuperseded
        put("cessation-of-operation", 5); // OriginalUseNoLongerValid
    }};

    public TppConnector(Tpp tpp) {
        this.tpp = tpp;
    }

    @Override
    public ConnectorType getType() {
        return ConnectorType.TPP;
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
            throw new VCertException(format("ping failed with status %d and reason %s", response.status(), response.reason()));
        }
    }

    private Response doPing() {
        return tpp.ping(apiKey);
    }

    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        AuthorizeResponse response = tpp.authorize(new AuthorizeRequest(auth.user(), auth.password()));
        apiKey = response.apiKey();
        bestBeforeEnd = response.validUntil();
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
        VCertException.throwIfNull(zone, "empty zone");
        ReadZoneConfigurationRequest request = new ReadZoneConfigurationRequest(getPolicyDN(zone));
        ReadZoneConfigurationResponse response = tpp.readZoneConfiguration(request, apiKey);
        ServerPolicy serverPolicy = response.policy();
        Policy policy = serverPolicy.toPolicy();
        ZoneConfiguration zoneConfig = serverPolicy.toZoneConfig();
        zoneConfig.policy(policy);
        return zoneConfig;
    }

    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request) throws VCertException {
        // todo: should one really have to pass a request into a "generate request" method?
        if(config == null) {
            config = readZoneConfiguration(zone);
        }
        String tppMgmtType = config.customAttributeValues().get(tppAttributeManagementType);
        if("Monitoring".equals(tppMgmtType) || "Unassigned".equals(tppMgmtType)) {
            throw new VCertException("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed");
        }

        config.updateCertificateRequest(request);

        switch(request.csrOrigin()) {
            case LocalGeneratedCSR: {
                if("0".equals(config.customAttributeValues().get(tppAttributeManualCSR))) {
                    throw new VCertException("Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0");
                }
                request.generatePrivateKey();
                request.generateCSR();
                break;
            }
            case UserProvidedCSR: {
                if("0".equals(config.customAttributeValues().get(tppAttributeManualCSR))) {
                    throw new VCertException("Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0");
                }
                request.generatePrivateKey();
                if(Is.blank(request.csr())) {
                    throw new VCertException("CSR was supposed to be provided by user, but it's empty");
                }
                break;
            }
            case ServiceGeneratedCSR: {
                request.csr(null);
                break;
            }
        }
        return request; // TODO: should we return the request we modified? It's not a copy, it's the one that was passed in, mutated.
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone) throws VCertException {
        if(Is.blank(zone)) {
            zone = this.zone;
        }
        CertificateRequestsPayload payload = prepareRequest(request, zone);
        String requestId = tpp.requestCertificate(payload, apiKey);
        request.pickupId(requestId);
        return requestId;
    }

    private CertificateRequestsPayload prepareRequest(CertificateRequest request, String zone) throws VCertException {
        CertificateRequestsPayload payload;
        switch(request.csrOrigin()) {
            case LocalGeneratedCSR:
            case UserProvidedCSR:
                payload = new CertificateRequestsPayload()
                        .policyDN(getPolicyDN(zone))
                        .pkcs10(new String(request.csr()))
                        .objectName(request.friendlyName())
                        .disableAutomaticRenewal(true);
                break;
            case ServiceGeneratedCSR:
                payload = new CertificateRequestsPayload()
                        .policyDN(getPolicyDN(zone))
                        .objectName(request.friendlyName())
                        .subject(request.subject().commonName())  // TODO (Go SDK): there is some problem because Subject is not only CN
                        .subjectAltNames(wrapAltNames(request))
                        .disableAutomaticRenewal(true);
                break;
            default:
                throw new VCertException(MessageFormat.format("Unexpected option in PrivateKeyOrigin: {0}", request.csrOrigin()));
        }

        switch(request.keyType()) {
            case RSA: {
                payload.keyAlgorithm(PublicKeyAlgorithm.RSA.name());
                payload.keyBitSize(request.keyLength());
                break;
            }
            case ECDSA: {
                payload.keyAlgorithm("ECC");
                payload.ellipticCurve(request.keyCurve().name());
                break;
            }
        }
        return payload;
    }

    private Collection<SANItem> wrapAltNames(CertificateRequest request) {
        List<SANItem> sanItems = new ArrayList<>();
        sanItems.addAll(toSanItems(request.emailAddresses(), 1));
        sanItems.addAll(toSanItems(request.dnsNames(), 2));
        sanItems.addAll(toSanItems(request.ipAddresses(), 7));
        return sanItems;
    }

    private List<SANItem> toSanItems(Collection<?> collection, int type) {
        return Optional
                .ofNullable(collection)
                .orElse(Collections.emptyList())
                .stream()
                .filter(Objects::nonNull)
                .map(entry -> new SANItem().type(type).name(entry.toString()))
                .collect(toList());
    }

    @Override
    public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
        boolean includeChain = request.chainOption() != ChainOption.ChainOptionIgnore;
        boolean rootFirstOrder = includeChain && request.chainOption() == ChainOption.ChainOptionRootFirst;

        if(isNotBlank(request.pickupId()) && isNotBlank(request.thumbprint())) {
            Tpp.CertificateSearchResponse searchResult = searchCertificatesByFingerprint(request.thumbprint());
            if(searchResult.certificates().size() == 0) {
                throw new VCertException(format("No certifiate found using fingerprint %s", request.thumbprint()));
            }
            if(searchResult.certificates().size() > 1) {
                throw new VCertException(format("Error: more than one CertificateRequestId was found with the same thumbprint %s", request.thumbprint()));
            }
            request.pickupId(searchResult.certificates().get(0).certificateRequestId());
        }

        CertificateRetrieveRequest certReq = new CertificateRetrieveRequest()
                .certificateDN(request.pickupId())
                .format("base64")
                .rootFirstOrder(rootFirstOrder)
                .includeChain(includeChain);

        if(request.csrOrigin() == CsrOriginOption.ServiceGeneratedCSR || request.fetchPrivateKey()) {
            certReq.includePrivateKey(true);
            certReq.password(request.keyPassword());
        }

        // TODO move this retry logic to feign client
        Instant startTime = Instant.now();
        while(true) {
            CertificateRetrieveResponse retrieveResponse = retrieveCertificateOnce(certReq);
            if(isNotBlank(retrieveResponse.certificateData())) {
                PEMCollection pemCollection = PEMCollection.fromResponse(retrieveResponse.certificateData(), request.chainOption());
                request.checkCertificate(pemCollection.certificate());
                return pemCollection;
            }

            if(ZERO.equals(request.timeout())) {
                throw new VCertException(format("Failed to retrieve certificate %s. Status %s", request.pickupId(), retrieveResponse.status()));
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
    }

    private CertificateRetrieveResponse retrieveCertificateOnce(CertificateRetrieveRequest certificateRetrieveRequest) {
        return tpp.certificateRetrieve(certificateRetrieveRequest, apiKey);
    }

    @Data
    class CertificateRetrieveRequest {
        private String certificateDN;
        private String format;
        private String password;
        private boolean includePrivateKey;
        private boolean includeChain;
        private String friendlyName;
        private boolean rootFirstOrder;
    }

    @Data
    class CertificateRetrieveResponse {
        private String certificateData;
        private String format;
        private String filename;
        private String status;
        private int stage;
    }

    @Data
    class CertificateRevokeRequest {
        private String certificateDN;
        private String thumbprint;
        private Integer reason;
        private String comments;
        private boolean disable;
    }

    @Data
    class CertificateRevokeResponse {
        private boolean requested;
        private boolean success;
        private String error;
    }

    private Tpp.CertificateSearchResponse searchCertificatesByFingerprint(String fingerprint) {
        String cleanFingerprint = fingerprint
                .replaceAll(":", "")
                .replaceAll("/.", "")
                .toUpperCase();

        return searchCertificates(Collections.singletonList(format("Thumbprint=%s", cleanFingerprint)));
    }

    private Tpp.CertificateSearchResponse searchCertificates(List<String> searchRequest) {
        return tpp.searchCertificates(Strings.join(searchRequest, "&"), apiKey);
    }

    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        Integer reason = revocationReasons.get(request.reason());
        if(reason == null) {
            throw new VCertException(format("could not parse revocation reason `%s`", request.reason()));
        }

        CertificateRevokeRequest revokeRequest = new CertificateRevokeRequest()
                .certificateDN(request.certificateDN())
                .thumbprint(request.thumbprint())
                .reason(reason)
                .comments(request.comments())
                .disable(request.disable());

        CertificateRevokeResponse revokeResponse = revokeCertificate(revokeRequest);
        if(!revokeResponse.success()) {
            throw new VCertException(format("Revocation error: %s", revokeResponse.error()));
        }
    }

    private CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) {
        return tpp.revokeCertificate(request, apiKey);
    }

    @Override

    public String renewCertificate(RenewalRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public ImportResponse importCertificate(ImportRequest request) throws VCertException {
        if(isBlank(request.policyDN())) {
            request.policyDN(getPolicyDN(zone));
        }

        return doImportCertificate(request);
    }

    private ImportResponse doImportCertificate(ImportRequest request) {
        return tpp.importCertificate(request, apiKey);
    }

    @Override
    public Policy readPolicyConfiguration(String zone) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @VisibleForTesting
    String getPolicyDN(final String zone) {
        String result = zone;
        Matcher candidate = policy.matcher(zone);
        if(!candidate.matches()) {
            if(!policy.matcher(zone).matches()) {
                result = "\\" + result;
            }
            result = "\\VED\\Policy" + result;
        }
        return result;
    }

    @Data
    @AllArgsConstructor
    static class AuthorizeRequest {
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class ReadZoneConfigurationRequest {
        String policyDN;
    }

    @Data
    @SuppressWarnings("WeakerAccess")
    public static class ReadZoneConfigurationResponse {
        Object error;
        ServerPolicy policy;
    }

    @Data
    static class CertificateRequestsPayload {
        @SerializedName("PolicyDN")
        private String policyDN;
        @SerializedName("CADN")
        private String cadn;
        private String objectName;
        private String subject;
        private String organizationalUnit;
        private String organization;
        private String city;
        private String state;
        private String country;
        private Collection<SANItem> subjectAltNames;
        private String contact;
        @SerializedName("CASpecificAttributes")
        private Collection<NameValuePair<String, String>> caSpecificAttributes;
        @SerializedName("PKCS10")
        private String pkcs10;
        private String keyAlgorithm;
        private int keyBitSize;
        private String ellipticCurve;
        private boolean disableAutomaticRenewal;
    }

    @Data
    private static class SANItem {
        private int type;
        private String name;
    }

    @Data
    private static class NameValuePair<K, V> {
        private K key;
        private V value;
    }
}
