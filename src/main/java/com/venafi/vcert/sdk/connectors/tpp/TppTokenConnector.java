package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.*;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.Is;
import feign.FeignException;
import feign.Response;
import lombok.Setter;

import java.net.InetAddress;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;
import static java.time.Duration.ZERO;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class TppTokenConnector extends AbstractTppConnector implements TokenConnector {

    public TppTokenConnector(Tpp tpp){ super(tpp); }
    @Setter
    private Authentication credentials;

    @Override
    public ConnectorType getType() {
        return ConnectorType.TPP_TOKEN;
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
    public void setVendorAndProductName(String vendorAndProductName) {
        this.vendorAndProductName = vendorAndProductName;
    }

    @Override
    public String getVendorAndProductName() {
        return vendorAndProductName;
    }

    private String getAuthHeaderValue() throws VCertException {
        if(isBlank(credentials.accessToken())){
            throw new VCertException("Token cannot be empty");
        }

        return String.format(HEADER_VALUE_AUTHORIZATION, credentials.accessToken());
    }

    @Override
    public void ping() throws VCertException {
        Response response = doPing();
        if (response.status() != 200) {
            throw new VCertException(
                    format("ping failed with status %d and reason %s", response.status(), response.reason()));
        }
    }

    private Response doPing() throws VCertException{
        return tpp.pingToken(getAuthHeaderValue());
    }

    @Override
    public TokenInfo getAccessToken(Authentication auth) throws VCertException {

        VCertException.throwIfNull( auth, MISSING_CREDENTIALS_MESSAGE );

        AuthorizeTokenRequest info = new AuthorizeTokenRequest( auth.user(), auth.password(), auth.clientId(), auth.scope(), auth.state(), auth.redirectUri() );
        AuthorizeTokenResponse response = tpp.authorizeToken( info );
        TokenInfo accessTokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(), response.tokenType(), response.scope(), response.identity(), response.refreshUntil());

        this.credentials = auth;
        this.credentials.accessToken(accessTokenInfo.accessToken());
        this.credentials.refreshToken(accessTokenInfo.refreshToken());

        return accessTokenInfo;
    }

    @Override
    public TokenInfo refreshAccessToken(String clientId ) throws VCertException{
        if(isBlank(credentials.refreshToken())){
            throw new VCertException(MISSING_REFRESH_TOKEN_MESSAGE);
        }
        try {
            RefreshTokenRequest request = new RefreshTokenRequest(credentials.refreshToken(), clientId);
            RefreshTokenResponse response = tpp.refreshToken( request );

            TokenInfo tokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(),
                    response.tokenType(), response.scope(), "",
                    response.refreshUntil());

            this.credentials.accessToken(tokenInfo.accessToken());
            this.credentials.refreshToken(tokenInfo.refreshToken());

            return tokenInfo;
        }catch (FeignException.BadRequest e){
            throw new VCertException(e.getMessage());
        }
    }

    @Override
    public int revokeAccessToken() throws VCertException {

        String requestHeader = getAuthHeaderValue();//"Bearer "+accessToken;

        Response response = tpp.revokeToken( requestHeader );
        if(response.status() == 200){
            return response.status();
        }else{
            throw new VCertException(response.toString());
        }
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
        VCertException.throwIfNull(zone, "empty zone");
        ReadZoneConfigurationRequest request = new ReadZoneConfigurationRequest(getPolicyDN(zone));
        ReadZoneConfigurationResponse response = tpp.readZoneConfigurationToken(request, getAuthHeaderValue());
        ServerPolicy serverPolicy = response.policy();
        Policy policy = serverPolicy.toPolicy();
        ZoneConfiguration zoneConfig = serverPolicy.toZoneConfig();
        zoneConfig.policy(policy);
        zoneConfig.zoneId(zone);
        return zoneConfig;
    }

    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request) throws VCertException {
        // todo: should one really have to pass a request into a "generate request" method?
        if (config == null) {
            config = readZoneConfiguration(zone);
        }
        String tppMgmtType = config.customAttributeValues().get(TPP_ATTRIBUTE_MANAGEMENT_TYPE);
        if ("Monitoring".equals(tppMgmtType) || "Unassigned".equals(tppMgmtType)) {
            throw new VCertException(
                    "Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed");
        }

        config.applyCertificateRequestDefaultSettingsIfNeeded(request);

        switch (request.csrOrigin()) {
            case LocalGeneratedCSR: {
                if ("0".equals(config.customAttributeValues().get(TPP_ATTRIBUTE_MANUAL_CSR))) {
                    throw new VCertException(
                            "Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0");
                }
                request.generatePrivateKey();
                request.generateCSR();
                break;
            }
            case UserProvidedCSR: {
                if ("0".equals(config.customAttributeValues().get(TPP_ATTRIBUTE_MANUAL_CSR))) {
                    throw new VCertException(
                            "Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0");
                }
                if (Is.blank(request.csr())) {
                    throw new VCertException("CSR was supposed to be provided by user, but it's empty");
                }
                break;
            }
            case ServiceGeneratedCSR: {
                request.csr(null);
                break;
            }
        }

        // TODO: should we return the request we modified? It's not a copy, it's the one that was passed in, mutated.
        return request;
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone) throws VCertException {
        return requestCertificate(request, new ZoneConfiguration().zoneId(zone));
    }

    @Override
    public String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration)
            throws VCertException {
        if (isBlank(zoneConfiguration.zoneId())) {
            zoneConfiguration.zoneId(this.zone);
        }
        CertificateRequestsPayload payload = prepareRequest(request, zoneConfiguration.zoneId());
        Tpp.CertificateRequestResponse response = tpp.requestCertificateToken(payload, getAuthHeaderValue());
        String requestId = response.certificateDN();
        request.pickupId(requestId);
        return requestId;
    }

    private CertificateRequestsPayload prepareRequest(CertificateRequest request, String zone)
            throws VCertException {
        CertificateRequestsPayload payload;
        Collection<NameValuePair<String, String>> caSpecificAttributes =
                new ArrayList<NameValuePair<String, String>>();

        // Workaround to send Origin to TPP versions that does not support it in the payload
        if (!isBlank(vendorAndProductName)) {
            caSpecificAttributes.add(new NameValuePair<String, String>("Origin", vendorAndProductName));
        }

        switch (request.csrOrigin()) {
            case LocalGeneratedCSR:
                payload = new CertificateRequestsPayload().policyDN(getPolicyDN(zone))
                        .pkcs10(new String(request.csr())).objectName(request.friendlyName())
                        .disableAutomaticRenewal(true).origin(vendorAndProductName)
                        .caSpecificAttributes(caSpecificAttributes);
                break;
            case UserProvidedCSR:
                payload = new CertificateRequestsPayload().policyDN(getPolicyDN(zone))
                        .pkcs10(new String(request.csr())).objectName(request.friendlyName())
                        .subjectAltNames(wrapAltNames(request)).disableAutomaticRenewal(true)
                        .origin(vendorAndProductName).caSpecificAttributes(caSpecificAttributes);
                break;
            case ServiceGeneratedCSR:
                payload = new CertificateRequestsPayload().policyDN(getPolicyDN(zone))
                        .objectName(request.friendlyName()).subject(request.subject().commonName()) // TODO (Go
                        // SDK):
                        // there is
                        // some
                        // problem
                        // because
                        // Subject
                        // is not
                        // only CN
                        .subjectAltNames(wrapAltNames(request)).disableAutomaticRenewal(true)
                        .origin(vendorAndProductName).caSpecificAttributes(caSpecificAttributes);
                break;
            default:
                throw new VCertException(MessageFormat.format("Unexpected option in PrivateKeyOrigin: {0}",
                        request.csrOrigin()));
        }

        if (request.keyType() == null) {
            request.keyType(KeyType.defaultKeyType());
        }

        switch (request.keyType()) {
            case RSA: {
                payload.keyAlgorithm(PublicKeyAlgorithm.RSA.name());
                payload.keyBitSize(request.keyLength());
                break;
            }
            case ECDSA: {
                payload.keyAlgorithm("ECC");
                payload.ellipticCurve(request.keyCurve().value());
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
        return Optional.ofNullable(collection).orElse(Collections.emptyList()).stream()
                .filter(Objects::nonNull)
                .map(entry -> new SANItem().type(type)
                        .name(type == 7 ? ((InetAddress) entry).getHostAddress() : entry.toString()))
                .collect(toList());
    }

    @Override
    public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
        boolean includeChain = request.chainOption() != ChainOption.ChainOptionIgnore;
        boolean rootFirstOrder =
                includeChain && request.chainOption() == ChainOption.ChainOptionRootFirst;

        if (isNotBlank(request.pickupId()) && isNotBlank(request.thumbprint())) {
            Tpp.CertificateSearchResponse searchResult =
                    searchCertificatesByFingerprint(request.thumbprint());
            if (searchResult.certificates().size() == 0) {
                throw new VCertException(
                        format("No certificate found using fingerprint %s", request.thumbprint()));
            }
            if (searchResult.certificates().size() > 1) {
                throw new VCertException(format(
                        "Error: more than one CertificateRequestId was found with the same thumbprint %s",
                        request.thumbprint()));
            }
            request.pickupId(searchResult.certificates().get(0).certificateRequestId());
        }

        CertificateRetrieveRequest certReq =
                new CertificateRetrieveRequest().certificateDN(request.pickupId()).format("base64")
                        .rootFirstOrder(rootFirstOrder).includeChain(includeChain);

        if (request.csrOrigin() == CsrOriginOption.ServiceGeneratedCSR || request.fetchPrivateKey()) {
            certReq.includePrivateKey(true);
            certReq.password(request.keyPassword());
        }

        // TODO move this retry logic to feign client
        Instant startTime = Instant.now();
        while (true) {
            Tpp.CertificateRetrieveResponse retrieveResponse = retrieveCertificateOnce(certReq);
            if (isNotBlank(retrieveResponse.certificateData())) {
                PEMCollection pemCollection = PEMCollection.fromResponse(
                        org.bouncycastle.util.Strings
                                .fromByteArray(Base64.getDecoder().decode(retrieveResponse.certificateData())),
                        request.chainOption(), request.privateKey());
                request.checkCertificate(pemCollection.certificate());
                return pemCollection;
            }

            if (ZERO.equals(request.timeout())) {
                throw new VCertException(format("Failed to retrieve certificate %s. Status %s",
                        request.pickupId(), retrieveResponse.status()));
            }

            if (Instant.now().isAfter(startTime.plus(request.timeout()))) {
                throw new VCertException(
                        format("Timeout trying to retrieve certificate %s", request.pickupId()));
            }

            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new VCertException("Error attempting to retry", e);
            }
        }
    }

    private Tpp.CertificateRetrieveResponse retrieveCertificateOnce(
            CertificateRetrieveRequest certificateRetrieveRequest) throws VCertException {
        return tpp.certificateRetrieveToken(certificateRetrieveRequest, getAuthHeaderValue());
    }


    private Tpp.CertificateSearchResponse searchCertificatesByFingerprint(String fingerprint) throws VCertException {
        final Map<String, String> searchRequest = new HashMap<String, String>();
        searchRequest.put("Thumbprint", fingerprint);

        return searchCertificates(searchRequest);
    }

    private Tpp.CertificateSearchResponse searchCertificates(Map<String, String> searchRequest) throws VCertException {
        return tpp.searchCertificatesToken(searchRequest, getAuthHeaderValue());
    }

    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        Integer reason = revocationReasons.get(request.reason());
        if (reason == null) {
            throw new VCertException(format("could not parse revocation reason `%s`", request.reason()));
        }

        CertificateRevokeRequest revokeRequest = new CertificateRevokeRequest()
                .certificateDN(request.certificateDN()).thumbprint(request.thumbprint()).reason(reason)
                .comments(request.comments()).disable(request.disable());

        Tpp.CertificateRevokeResponse revokeResponse = revokeCertificate(revokeRequest);
        if (!revokeResponse.success()) {
            throw new VCertException(format("Revocation error: %s", revokeResponse.error()));
        }
    }

    private Tpp.CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) throws VCertException {
        return tpp.revokeCertificateToken(request, getAuthHeaderValue());
    }

    @Override
    public String renewCertificate(RenewalRequest request) throws VCertException {
        String certificateDN;

        if (isNotBlank(request.thumbprint()) && isBlank(request.certificateDN())) {
            Tpp.CertificateSearchResponse searchResult =
                    searchCertificatesByFingerprint(request.thumbprint());
            if (searchResult.certificates().isEmpty()) {
                throw new VCertException(
                        String.format("No certificate found using fingerprint %s", request.thumbprint()));
            }
            if (searchResult.certificates().size() > 1) {
                throw new VCertException(
                        String.format("More than one certificate was found with the same thumbprint"));
            }
            certificateDN = searchResult.certificates().get(0).certificateRequestId();
        } else {
            certificateDN = request.certificateDN();
        }

        if (isNull(certificateDN)) {
            throw new VCertException(
                    "Failed to create renewal request: CertificateDN or Thumbprint required");
        }

        final CertificateRenewalRequest renewalRequest = new CertificateRenewalRequest();
        renewalRequest.certificateDN(certificateDN);

        if (Objects.nonNull(request.request()) && request.request().csr().length > 0) {
            String pkcs10 = org.bouncycastle.util.Strings.fromByteArray(request.request().csr());
            renewalRequest.PKCS10(pkcs10);
        }

        final Tpp.CertificateRenewalResponse response = tpp.renewCertificateToken(renewalRequest, getAuthHeaderValue());
        if (!response.success()) {
            throw new VCertException(String.format("Certificate renewal error: %s", response.error()));
        }

        return certificateDN;
    }


    @Override
    public ImportResponse importCertificate(ImportRequest request) throws VCertException {
        if (isBlank(request.policyDN())) {
            request.policyDN(getPolicyDN(zone));
        }

        return doImportCertificate(request);
    }

    private ImportResponse doImportCertificate(ImportRequest request) throws VCertException {
        return tpp.importCertificateToken(request, getAuthHeaderValue());
    }

    @Override
    public Policy readPolicyConfiguration(String zone) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }
}
