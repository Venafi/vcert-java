package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.ConnectorException.*;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequestResponse;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policy.converter.TPPPolicySpecificationConverter;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.utils.Is;
import com.venafi.vcert.sdk.utils.VCertUtils;
import feign.FeignException.BadRequest;
import feign.FeignException.Unauthorized;
import feign.Response;
import lombok.Getter;

import java.net.InetAddress;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.time.Duration.ZERO;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;


public class TppConnector extends AbstractTppConnector implements Connector {
  @VisibleForTesting
  OffsetDateTime bestBeforeEnd;
  @Getter
  private String apiKey;

  protected Authentication credentials;

  public TppConnector(Tpp tpp) {
    super(tpp);
  }

  @Override
  public Authentication getCredentials() {
    return credentials;
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
  public void setVendorAndProductName(String vendorAndProductName) {
    this.vendorAndProductName = vendorAndProductName;
  }

  @Override
  public String getVendorAndProductName() {
    return vendorAndProductName;
  }

  @Override
  public void ping() throws VCertException {
    Response response = tppAPI.ping();
    if (response.status() != 200)
      throw new TppPingException(response.status(), response.reason());
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: For this implementation is being invoked the {@link Tpp#authorize(AuthorizeRequest)} to 
   * get the authorization details.
   * Also the credentials given replaces the credentials hold by this instance until 
   * this moment and additionally the {@link #apiKey} and {@link #bestBeforeEnd} attributes are determined.
   *
   * @throws VCertException if the call to {@link Tpp#authorize(AuthorizeRequest)} throws a {@link Unauthorized} or {@link BadRequest}
   */
  @Override
  public void authorize(Authentication credentials) throws VCertException {
    try {
      AuthorizeResponse response = tpp.authorize(new AuthorizeRequest(credentials.user(), credentials.password()));
      apiKey = response.apiKey();
      bestBeforeEnd = response.validUntil();
      this.credentials = credentials;
      this.credentials.apiKey(apiKey);
    }  catch(Unauthorized | BadRequest e){
      throw VCertException.fromFeignException(e);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean isEmptyCredentials(Authentication credentials){
    if(credentials == null){
      return true;
    }

    return isBlank(credentials.user()) || isBlank(credentials.password());
  }

  @Override
  public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
    VCertException.throwIfNull(zone, "empty zone");
    ReadZoneConfigurationRequest request = new ReadZoneConfigurationRequest(getPolicyDN(zone));
    ReadZoneConfigurationResponse response = tppAPI.readZoneConfiguration(request);
    ServerPolicy serverPolicy = response.policy();
    Policy policy = serverPolicy.toPolicy();
    ZoneConfiguration zoneConfig = serverPolicy.toZoneConfig();
    zoneConfig.policy(policy);
    zoneConfig.zoneId(zone);
    return zoneConfig;
  }

  @Override
  public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request)
      throws VCertException {
    // todo: should one really have to pass a request into a "generate request" method?
    if (config == null) {
      config = readZoneConfiguration(zone);
    }
    String tppMgmtType = config.customAttributeValues().get(TPP_ATTRIBUTE_MANAGEMENT_TYPE);
    if ("Monitoring".equals(tppMgmtType) || "Unassigned".equals(tppMgmtType))
      throw new TppRequestCertificateNotAllowedException();

    config.applyCertificateRequestDefaultSettingsIfNeeded(request);

    switch (request.csrOrigin()) {
      case LocalGeneratedCSR: {
        if ("0".equals(config.customAttributeValues().get(TPP_ATTRIBUTE_MANUAL_CSR)))
          throw new TppManualCSRNotEnabledException(request.csrOrigin());

        request.generatePrivateKey();
        request.generateCSR();
        break;
      }
      case UserProvidedCSR: {
        if ("0".equals(config.customAttributeValues().get(TPP_ATTRIBUTE_MANUAL_CSR)))
          throw new TppManualCSRNotEnabledException(request.csrOrigin());

        if (Is.blank(request.csr()))
          throw new CSRNotProvidedByUserException();

        break;
      }
      case ServiceGeneratedCSR: {
        request.csr(null);
        break;
      }
    }
    return request; // TODO: should we return the request we modified? It's not a copy, it's the one
    // that was passed in, mutated.
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
    Tpp.CertificateRequestResponse response = tppAPI.requestCertificate(payload);
    String requestId = response.certificateDN();
    request.pickupId(requestId);
    return requestId;
  }

  protected CertificateRequestsPayload prepareRequest(CertificateRequest request, String zone)
      throws VCertException {
    CertificateRequestsPayload payload;
    Collection<NameValuePair<String, String>> caSpecificAttributes = new ArrayList<>();

    // Workaround to send Origin to TPP versions that does not support it in the payload
    if (!isBlank(vendorAndProductName)) {
      caSpecificAttributes.add(new NameValuePair<>("Origin", vendorAndProductName));
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


    //support for validity hours begins
    VCertUtils.addExpirationDateAttribute(request, payload);
    //support for validity hours ends

    //support for custom fields begins
    VCertUtils.addCustomFieldsToRequest(request, payload);
    //support for custom fields ends

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
      if (searchResult.certificates().size() == 0)
        throw new CertificateNotFoundByThumbprintException(request.thumbprint());

      if (searchResult.certificates().size() > 1)
        throw new MoreThanOneCertificateWithSameThumbprintException(request.thumbprint());

      request.pickupId(searchResult.certificates().get(0).certificateRequestId());
    }

    CertificateRetrieveRequest certReq = new CertificateRetrieveRequest()
        .certificateDN(request.pickupId())
        .format(request.dataFormat() == DataFormat.PKCS8 ? PKCS8_DATA_FORMAT : LEGACY_DATA_FORMAT)
        .rootFirstOrder(rootFirstOrder)
        .includeChain(includeChain);

    if (request.csrOrigin() == CsrOriginOption.ServiceGeneratedCSR || request.fetchPrivateKey()) {
      certReq.includePrivateKey(true);
      certReq.password(request.keyPassword());
    }

    // TODO move this retry logic to feign client
    Instant startTime = Instant.now();
    while (true) {
      Tpp.CertificateRetrieveResponse retrieveResponse = retrieveCertificateOnce(certReq);
      if (isNotBlank(retrieveResponse.certificateData())) {
        PEMCollection pemCollection = PEMCollection.fromStringPEMCollection(
            org.bouncycastle.util.Strings
                .fromByteArray(Base64.getDecoder().decode(retrieveResponse.certificateData())),
            request.chainOption(), request.privateKey(), request.keyPassword(), request.dataFormat());
        request.checkCertificate(pemCollection.certificate());
        return pemCollection;
      }

      if (ZERO.equals(request.timeout()))
        throw new CertificatePendingException(request.pickupId());

      if (Instant.now().isAfter(startTime.plus(request.timeout())))
        throw new RetrieveCertificateTimeoutException(request.pickupId());

      try {
        TimeUnit.SECONDS.sleep(2);
      } catch (InterruptedException e) {
        // Restore interrupted state...
        Thread.currentThread().interrupt();
        throw new AttemptToRetryException(e);
      }
    }
  }

  private Tpp.CertificateRetrieveResponse retrieveCertificateOnce(
      CertificateRetrieveRequest certificateRetrieveRequest) throws VCertException {
    return tppAPI.certificateRetrieve(certificateRetrieveRequest);
  }


  private Tpp.CertificateSearchResponse searchCertificatesByFingerprint(String fingerprint) throws VCertException {
    final Map<String, String> searchRequest = new HashMap<>();
    searchRequest.put("Thumbprint", fingerprint);

    return searchCertificates(searchRequest);
  }

  private Tpp.CertificateSearchResponse searchCertificates(Map<String, String> searchRequest) throws VCertException {
    return tppAPI.searchCertificates(searchRequest);
  }

  @Override
  public void revokeCertificate(RevocationRequest request) throws VCertException {
    Integer reason = revocationReasons.get(request.reason());
    if (reason == null)
      throw new CouldNotParseRevokeReasonException(request.reason());

    CertificateRevokeRequest revokeRequest = new CertificateRevokeRequest()
        .certificateDN(request.certificateDN()).thumbprint(request.thumbprint()).reason(reason)
        .comments(request.comments()).disable(request.disable());

    Tpp.CertificateRevokeResponse revokeResponse = revokeCertificate(revokeRequest);
    if (!revokeResponse.success())
      throw new RevokeFailureException(revokeResponse.error());
  }

  private Tpp.CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) throws VCertException {
    return tppAPI.revokeCertificate(request);
  }

  @Override
  public String renewCertificate(RenewalRequest request) throws VCertException {
    String certificateDN;

    if (isNotBlank(request.thumbprint()) && isBlank(request.certificateDN())) {
      Tpp.CertificateSearchResponse searchResult =
          searchCertificatesByFingerprint(request.thumbprint());
      if (searchResult.certificates().isEmpty())
        throw new CertificateNotFoundByThumbprintException(request.thumbprint());

      if (searchResult.certificates().size() > 1)
        throw new MoreThanOneCertificateWithSameThumbprintException(request.thumbprint());

      certificateDN = searchResult.certificates().get(0).certificateRequestId();
    } else {
      certificateDN = request.certificateDN();
    }

    if (isNull(certificateDN))
      throw new CertificateDNOrThumbprintWasNotProvidedException();

    final CertificateRenewalRequest renewalRequest = new CertificateRenewalRequest();
    renewalRequest.certificateDN(certificateDN);

    if (nonNull(request.request()) && nonNull(request.request().csr()) && request.request().csr().length > 0) {
      String pkcs10 = org.bouncycastle.util.Strings.fromByteArray(request.request().csr());
      renewalRequest.PKCS10(pkcs10);
    }

    final Tpp.CertificateRenewalResponse response = tppAPI.renewCertificate(renewalRequest);
    if (!response.success())
      throw new RenewFailureException(response.error());

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
    return tppAPI.importCertificate(request);
  }

  @Override
  public Policy readPolicyConfiguration(String zone) throws VCertException {
    throw new UnsupportedOperationException("Method not yet implemented");
  }

  @Override
  public void setPolicy(String policyName, PolicySpecification policySpecification) throws VCertException {
    try {
      TPPPolicy tppPolicy = TPPPolicySpecificationConverter.INSTANCE.convertFromPolicySpecification(policySpecification);
      String[] identitiesList = this.resolveTPPContacts(tppPolicy.contact());
      tppPolicy.contact(identitiesList);
      setPolicy(policyName, tppPolicy);
    }catch (Exception e){
      throw new VCertException(e);
    }
  }

  @Override
  public PolicySpecification getPolicy(String policyName) throws VCertException {
    PolicySpecification policySpecification;
    try {
      TPPPolicy tppPolicy = getTPPPolicy(policyName);

      policySpecification = TPPPolicySpecificationConverter.INSTANCE.convertToPolicySpecification( tppPolicy );

    }catch (Exception e){
      throw new VCertException(e);
    }

    return policySpecification;
  }

  @Override
  public String requestSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException {

    TppSshCertRequestResponse tppSshCertRequestResponse = super.requestTppSshCertificate(sshCertificateRequest);

    return tppSshCertRequestResponse.dn();
  }

  @Override
  public SshCertRetrieveDetails retrieveSshCertificate(SshCertificateRequest sshCertificateRequest)
      throws VCertException {
    return super.retrieveTppSshCertificate(sshCertificateRequest);
  }

  @Override
  public SshConfig retrieveSshConfig(SshCaTemplateRequest sshCaTemplateRequest) throws VCertException {
    return super.retrieveTppSshConfig(sshCaTemplateRequest);
  }

  @Override
  protected TppAPI getTppAPI() {
    if(tppAPI == null){
      tppAPI = new TppAPI(tpp) {

        @Override
        String getAuthKey() throws VCertException {
          if(apiKey() == null)
            throw new VCertException("API Key is null");

          return apiKey();
        }
      };
    }
    return tppAPI;
  }
}
