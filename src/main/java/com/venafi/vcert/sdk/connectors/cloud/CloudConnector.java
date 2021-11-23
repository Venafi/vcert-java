package com.venafi.vcert.sdk.connectors.cloud;

import static com.venafi.vcert.sdk.connectors.ConnectorException.*;
import static java.lang.String.format;
import static java.time.Duration.ZERO;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.venafi.vcert.sdk.connectors.cloud.domain.*;
import com.venafi.vcert.sdk.connectors.cloud.endpoint.KeystoreRequest;
import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.policy.converter.CloudPolicySpecificationConverter;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.Strings;

import com.google.common.io.CharStreams;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.CertificateStatus;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.certificate.SshCaTemplateRequest;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.certificate.SshConfig;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.VCertUtils;

import feign.Response;
import lombok.Data;
import lombok.Getter;
	
public class CloudConnector implements Connector {
	
	private static String APPLICATION_SERVER_TYPE_ID = "784938d1-ef0d-11eb-9461-7bb533ba575b";

  private Cloud cloud;

  @Getter
  private UserDetails user;
  private Authentication auth;
  private String zone;
  @Getter
  private String vendorAndProductName;

  public CloudConnector(Cloud cloud) {
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
  public void setVendorAndProductName(String vendorAndProductName) {
    this.vendorAndProductName = vendorAndProductName;
  }

  @Override
  public String getVendorAndProductName() {
    return vendorAndProductName;
  }

  @Override
  public void ping() throws VCertException {
    Response response = doPing();
    if (response.status() != 200) {
      throw new CloudPingException( response.status(), response.reason());
    }
  }

  private Response doPing() {
    return cloud.ping(auth.apiKey());
  }

  @Override
  public void authenticate(Authentication auth) throws VCertException {
    VCertException.throwIfNull(auth, "Failed to authenticate: missing credentials");
    this.auth = auth;
    this.user = cloud.authorize(auth.apiKey());
  }

  @Override
  public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
	  
	  String valies[] = StringUtils.split(zone, "\\");
	  String appName = valies[0];
	  String citAlias = valies[1];
	  
	  CertificateIssuingTemplate cit = null;
	    String zoneId = null;
	    if((appName != null && appName != "") && (citAlias != null && citAlias != "")) {
	    	
	    	 cit = cloud.certificateIssuingTemplateByAppNameAndCitAlias(appName, citAlias, auth.apiKey());
	    	
	    }else {
	    	  throw new ZoneFormatException("The parameters: appName, citAlias or both are empty");
	    }
	    
	    //get application id.
	    Application app = cloud.applicationByName(appName, auth.apiKey());
	    String appId = app.id();

	    ZoneConfiguration zoneConfig = cit.toZoneConfig();
	    zoneConfig.policy(cit.toPolicy());
	    //zoneConfig.zoneId(zoneId);
	    zoneConfig.zoneId(zone);
	    zoneConfig.applicationId(appId);
	    zoneConfig.certificateIssuingTemplateId(cit.id());

	    return zoneConfig;
  }

  @Override
  public CertificateRequest generateRequest(ZoneConfiguration zoneConfig,
      CertificateRequest request) throws VCertException {
    switch (request.csrOrigin()) {
      case LocalGeneratedCSR:
        if (zoneConfig == null) {
          zoneConfig = readZoneConfiguration(zone);
        }
        zoneConfig.applyCertificateRequestDefaultSettingsIfNeeded(request);
        zoneConfig.validateCertificateRequest(request);
        request.generatePrivateKey();
        request.generateCSR();
        break;
      case UserProvidedCSR:
        if (request.csr().length == 0) {
          throw new CSRNotProvidedByUserException();
        }
        break;
      case ServiceGeneratedCSR:
        request.csr(null);
        break;
      default:
        throw new UnreconigzedCSROriginException(request.csrOrigin());
    }

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
	  
	  if (user == null || user.company() == null) {
		  throw new UserNotAuthenticatedException("Must be authenticated to request a certificate");
	  }
	  
	  CertificateRequestsPayload payload = buildRequestCertificatePayload(request, zoneConfiguration);
	  
	  CertificateRequestsResponse response =
			  cloud.certificateRequest( auth.apiKey(), payload );

	  String requestId = response.certificateRequests().get(0).id();
	  request.pickupId(requestId);
	  return requestId;
  }
  
  private CertificateRequestsPayload buildRequestCertificatePayload(CertificateRequest request, ZoneConfiguration zoneConfiguration) throws VCertException {

	  CertificateRequestsPayload payload = new CertificateRequestsPayload();
			  //.zoneId(zoneConfiguration.zoneId());

	  if (CsrOriginOption.ServiceGeneratedCSR == request.csrOrigin()) {
		  payload.isVaaSGenerated(true);
		  payload.applicationServerTypeId(APPLICATION_SERVER_TYPE_ID);
		  PolicySpecification policySpecification = getPolicy(zoneConfiguration.zoneId(), false);
		  payload.csrAttributes( CloudConnectorUtils.buildCsrAttributes(request, policySpecification));
		  
	  } else {
		  payload.csr(new String(request.csr()));
	  }
	  
	  //support for validity hours begins
	  if( request.validityHours() > 0 ) {	
		  String validityHours =  "PT" + request.validityHours() + "H";
		  payload.validityPeriod(validityHours);

	  }
	  //support for validity hours ends

	  //add certificateIssuingTemplate and applicationId
	  payload.applicationId(zoneConfiguration.applicationId());
	  payload.certificateIssuingTemplateId(zoneConfiguration.certificateIssuingTemplateId());

	  //add client information
	  VCertUtils.addApiClientInformation(payload);

	  return payload;
  }
  
  @Override
  public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
	  //The next logic is to try to ensure that the request.certId exists.
	  if (isBlank(request.certId()))
		  setCertId(request);

	  //At this point,it's sure that the request.certId exists
	  //Only it's required to determine whether the certificates was generated with a CSR generated on the server 
	  //or if that was generated with a CSR Local generated
	  return getCertificateAsPEMCollection(request);
  }
  
  /**
   * This method determines the certId and set it to the {@link CertificateRequest} object passed as argument.
   *  For that it will be used the {@link CertificateRequest#pickupId} to determine the certId. If that is not set 
   *  then it will be used the {@link CertificateRequest#thumbprint}. 
   * @param request
   * @throws VCertException if it was not possible to determine the certId using the values of picukpId or the thumbprint.
   */
  private void setCertId(CertificateRequest request) throws VCertException {
	  
	  if (isBlank(request.pickupId())) {
		  if (isNotBlank(request.thumbprint())) {
			  setIdentifiersUsingThumbprint(request);
			  if (isBlank(request.certId()) && isBlank(request.pickupId())) {
				  throw new UndeterminedCertIdException();
			  } else {
				  if (isBlank(request.certId()) && isNotBlank(request.pickupId())) {
					  request.certId(getCertificateIdFromPickupId(request));
				  }
			  }
		  } else {
			  throw new PickupIdOrThumbprintNotSetToGetCertIdException();
		  }
	  } else 
		  request.certId(getCertificateIdFromPickupId(request));
  }
  
  private void setIdentifiersUsingThumbprint(CertificateRequest request) throws VCertException {
	  String pickupId = null;
	  String certId = null;
	  
	  Cloud.CertificateSearchResponse certificateSearchResponse =
			  searchCertificatesByFingerprint(request.thumbprint());
	  if (certificateSearchResponse.certificates().size() == 0) {
		  throw new CertificateNotFoundByThumbprintException(request.thumbprint());
	  }

	  List<String> reqIds = new ArrayList<>();
	  boolean isOnlyOneCertificateRequestId = true;
	  for (Cloud.Certificate certificate : certificateSearchResponse.certificates()) {
		  reqIds.add(certificate.certificateRequestId());
		  if (isNotBlank(pickupId)
				  && !pickupId.equals(certificate.certificateRequestId())) {
			  isOnlyOneCertificateRequestId = false;
			  break;
		  }
		  if (isNotBlank(certificate.certificateRequestId())) {
			  pickupId = certificate.certificateRequestId();
		  }
		  
		  if (isNotBlank(certificate.id())) {
			  certId = certificate.id();
		  }
	  }
	  if (!isOnlyOneCertificateRequestId) {
		  throw new MoreThanOneCertificateRequestIdException(reqIds);
	  }
	  request.pickupId(pickupId);
	  request.certId(certId);
  }

  private String getCertificateIdFromPickupId(CertificateRequest request) throws VCertException {
	  CertificateStatus certificateStatus = null;

	  Instant startTime = Instant.now();
	  while (true) {

		  certificateStatus = getCertificateStatus(request.pickupId());
		  if ("ISSUED".equals(certificateStatus.status())) {
			  break;
		  } else if ("FAILED".equals(certificateStatus.status())) {
			  throw new CertificateStatusFailedException( certificateStatus.toString());
		  }

		  // Status either REQUESTED or PENDING
		  if (ZERO.equals(request.timeout())) {
			  throw new CertificatePendingException(request.pickupId());
		  }

		  if (Instant.now().isAfter(startTime.plus(request.timeout()))) {
			  throw new RetrieveCertificateTimeoutException(request.pickupId());
		  }

		  try {
			  TimeUnit.SECONDS.sleep(2);
		  } catch (InterruptedException e) {
			  e.printStackTrace();
			  throw new AttemptToRetryException(e);
		  }
	  }

	  if (user == null || user.company() == null) {
		  throw new UserNotAuthenticatedException("Must be authenticated to retieve certificate");
	  }

	  if(certificateStatus == null) {
		  throw new FailedToRetrieveCertificateStatusException(request.pickupId());
	  }

	  return certificateStatus.certificateIds().get(0);
  }

  private PEMCollection getCertificateAsPEMCollection(CertificateRequest request) throws VCertException {
	  String vaasChainOption = CloudConnectorUtils.getVaaSChainOption(request.chainOption());
	  
	  PEMCollection pemCollection = getCertificateAsPEMCollection(request, vaasChainOption);
	  
	  request.checkCertificate(pemCollection.certificate());
	  
	  return pemCollection;
  }
  
  private PEMCollection getCertificateAsPEMCollection(CertificateRequest request, String vaasChainOption) throws VCertException {
	  
	  CertificateDetails certificateDetails = cloud.certificateDetails(request.certId(), auth.apiKey());
	  
	  EdgeEncryptionKey edgeEncryptionKey = cloud.retrieveEdgeEncryptionKey(certificateDetails.dekHash(), auth.apiKey());
	  
	  if(isNotBlank(edgeEncryptionKey.key())) {
		  byte[] serverPublicKey = Base64.getDecoder().decode(edgeEncryptionKey.key());
		  return retrieveCertificateAsPemCollectionFromCSRServiceGenerated(request, serverPublicKey, vaasChainOption);
	  } else 
		  return retrieveCertificateAsPemCollectionFromCSRProvided(request, vaasChainOption);
  }

  private PEMCollection retrieveCertificateAsPemCollectionFromCSRProvided(CertificateRequest request, String chainOrder) throws VCertException {
	  String certificateAsPemString = "";
	  // We should decode this as is not REST, multiple decoders should be supported
	  // by feign as a potential improvement.
	  Instant startTime = Instant.now();
	  while (true) {

		  Response response = cloud.retrieveCertificate(request.certId(), auth.apiKey(), chainOrder);
		  if (response.status() == 200) {
			  try {
				  certificateAsPemString = CharStreams.toString(response.body().asReader());
				  break;
			  } catch (IOException e) {
				  throw new UnableToReadPEMCertificateException(request.certId());
			  }
		  }

		  // Status either REQUESTED or PENDING
		  if (ZERO.equals(request.timeout())) {
			  throw new CertificatePendingException(request.pickupId());
		  }

		  if (Instant.now().isAfter(startTime.plus(request.timeout()))) {
			  throw new RetrieveCertificateTimeoutException(request.pickupId());
		  }

		  try {
			  TimeUnit.SECONDS.sleep(2);
		  } catch (InterruptedException e) {
			  e.printStackTrace();
			  throw new AttemptToRetryException(e);
		  }
	  }
	  
	  return PEMCollection.fromResponse(
			  certificateAsPemString, 
			  request.chainOption(), 
			  request.privateKey(),
			  request.keyPassword());
  }
  
  private PEMCollection retrieveCertificateAsPemCollectionFromCSRServiceGenerated(CertificateRequest request, byte[] serverPublicKey, String chainOption) throws VCertException {

	  String encodedMessage = null;
	  try {
		  byte[] cipherText = SealedBoxUtility.crypto_box_seal(serverPublicKey, request.keyPassword().getBytes());
		  encodedMessage = Base64.getEncoder().encodeToString(cipherText);
	  } catch (Exception e) {
		  throw new VCertException(e);
	  }
	  
	  KeystoreRequest keystoreRequest = new KeystoreRequest()
			  .exportFormat("PEM")
			  .encryptedPrivateKeyPassphrase(encodedMessage)
			  .encryptedKeystorePassphrase("")
			  .certificateLabel("");
	  
	  InputStream keyStoreAsStream = null;
	  try {
		  Response response = cloud.retrieveKeystore(request.certId(), keystoreRequest, auth.apiKey());
		  keyStoreAsStream = response.body().asInputStream();
	  } catch (IOException e) {
		  throw new VCertException(e);
	  }
	  
	  return CloudConnectorUtils.getPEMCollectionFromKeyStoreAsStream(keyStoreAsStream, request.chainOption(), request.keyPassword());
  }
  
  /**
   * @deprecated
   * @param requestId
   * @return
   * @throws VCertException
   */
  public String certificateAsPem(String requestId) throws VCertException{
	  Response response = cloud.certificateAsPem(requestId, auth.apiKey());
	  if (response.status() != 200) {
		  throw new VCertException(String
				  .format("Invalid response fetching the certificate via CSR: %s", response.reason()));
	  }
	  try {
		  return CharStreams.toString(response.body().asReader());
	  } catch (IOException e) {
		  throw new VCertException("Unable to read the PEM certificate");
	  }
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

    if (isNotBlank(request.thumbprint())) {
      Cloud.CertificateSearchResponse result =
          this.searchCertificatesByFingerprint(request.thumbprint());
      Set<String> requestIds = result.certificates().stream().map(c -> c.certificateRequestId())
          .collect(Collectors.toSet());

      if (requestIds.size() > 1) {
        throw new MoreThanOneCertificateRequestIdException(request.thumbprint());
      } else if (requestIds.size() == 0) {
        throw new CertificateNotFoundByThumbprintException(request.thumbprint());
      }

      certificateRequestId = requestIds.iterator().next();

    } else if (isNotBlank(request.certificateDN())) {
      certificateRequestId = request.certificateDN();
    } else {
      throw new CertificateDNOrThumbprintWasNotProvidedException();
    }

    final CertificateStatus status = cloud.certificateStatus(certificateRequestId, auth.apiKey());
    
    String certificateId = status.certificateIds().get(0);
    
    
    CertificateDetails certDetails = cloud.certificateDetails(certificateId, auth.apiKey());
    
    if (!certDetails.certificateRequestId().equals(certificateRequestId)) {
      final StringBuilder errorStr = new StringBuilder();
      errorStr.append("Certificate under requestId %s ");
      errorStr.append(isNotBlank(request.thumbprint())
          ? String.format("with thumbprint %s ", request.thumbprint())
          : "");
      errorStr
          .append("is not the latest under ManagedCertificateId %s. The latest request is %s. ");
      errorStr.append("This error may happen when revoked certificate is requested to be renewed.");

      throw new VCertException(String.format(errorStr.toString(), certificateRequestId,
    		  certDetails.id(), certDetails.certificateRequestId()));
    }

    final CertificateRequestsPayload certificateRequest = new CertificateRequestsPayload();
    certificateRequest.existingCertificateId(certDetails.id());
    certificateRequest.applicationId(status.applicationId());
    certificateRequest.certificateIssuingTemplateId(status.certificateIssuingTemplateId());
    
    //add client information
    VCertUtils.addApiClientInformation(certificateRequest);
    
  
    certificateRequest
        .reuseCSR(!(Objects.nonNull(request.request()) && request.request().csr().length > 0));
    if (!certificateRequest.reuseCSR) {
      certificateRequest.csr(Strings.fromByteArray(request.request().csr()));
    }else {
    	throw new CSRNotProvidedException();
    }

    CertificateRequestsResponse response =
        cloud.certificateRequest(auth.apiKey(), certificateRequest);
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

  @Override
  public void setPolicy(String policyName, PolicySpecification policySpecification) throws VCertException {
    try {
      CloudPolicy cloudPolicy = CloudPolicySpecificationConverter.INSTANCE.convertFromPolicySpecification(policySpecification);
      CloudConnectorUtils.setCit(policyName, cloudPolicy.certificateIssuingTemplate(), cloudPolicy.caInfo(), auth.apiKey(), cloud);
    } catch ( Exception e ) {
      throw new VCertException(e);
    }
  }

  @Override
  public PolicySpecification getPolicy(String policyName) throws VCertException {
    return getPolicy(policyName, true);
  }
  
  private PolicySpecification getPolicy(String policyName, boolean removeRegexFromSubjectCN) throws VCertException {
	  PolicySpecification policySpecification;
	    try {
	      CloudPolicy cloudPolicy = CloudConnectorUtils.getCloudPolicy( policyName, auth.apiKey(), cloud );
	      cloudPolicy.removeRegexesFromSubjectCN(removeRegexFromSubjectCN);
	      policySpecification = CloudPolicySpecificationConverter.INSTANCE.convertToPolicySpecification( cloudPolicy );
	    }catch (Exception e){
	      throw new VCertException(e);
	    }

	    return policySpecification;
  }
  
  @Override
  public String requestSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException {
	  throw new UnsupportedOperationException("Method not yet implemented");
  }

  @Override
  public SshCertRetrieveDetails retrieveSshCertificate(SshCertificateRequest sshCertificateRequest)
  		throws VCertException {
	  throw new UnsupportedOperationException("Method not yet implemented");
  }
  
  @Override
  public SshConfig retrieveSshConfig(SshCaTemplateRequest sshCaTemplateRequest) throws VCertException {
	  throw new UnsupportedOperationException("Method not yet implemented");
  }

  private Cloud.CertificateSearchResponse searchCertificates(Cloud.SearchRequest searchRequest) {
    return cloud.searchCertificates(auth.apiKey(), searchRequest);
  }

  private Cloud.CertificateSearchResponse searchCertificatesByFingerprint(String fingerprint) {
    String cleanFingerprint = fingerprint.replaceAll(":", "").replaceAll("/.", "");

    return searchCertificates(Cloud.SearchRequest.findByFingerPrint(cleanFingerprint));
  }

  private String[] parseZoneIdentifiers(String zone) throws VCertException {
    try {
      // Check if zone is UUID
      UUID.fromString(zone);
      return new String[] {zone, null, null};
    } catch (IllegalArgumentException iae) {
      // The zone argument is not UUID, so we expect to be ProjectName\ZoneName
      String zoneParsed[] = zone.split(Pattern.quote("\\"));

      if (zoneParsed.length != 2) {
        throw new VCertException(format(
            "Invalid zone ID or path. We expect UUID or 'ProjectName\\ZoneName', but we got '%s'.",
            zone));
      }

      if (isBlank(zoneParsed[0])) {
        throw new VCertException(format("Unable to get Project Name from '%s'", zone));
      }

      if (isBlank(zoneParsed[1])) {
        throw new VCertException(format("Unable to get Zone Name from '%s'", zone));
      }
      return new String[] {null, zoneParsed[0], zoneParsed[1]};
    }
  }

  @Data
  public static class CertificateRequestsPayload {
    // private String companyId;
    // private String downloadFormat;
    @SerializedName("certificateSigningRequest")
    private String csr;
    private String zoneId;
    private String existingManagedCertificateId;
    private boolean reuseCSR;
    private String validityPeriod;
    private String applicationId;
    private String certificateIssuingTemplateId;
    private String existingCertificateId;
    private ApiClientInformation apiClientInformation;
    private boolean isVaaSGenerated;
    private CsrAttributes csrAttributes;
    private String applicationServerTypeId;
  }

  @Data
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
  
  @Data
  public static class ApiClientInformation{
	  String type;
	  String identifier;
  }
  
  @Data
  public static class CsrAttributes {
	  private String commonName;
	  private String organization;
	  private String[] organizationalUnits;
	  private String locality;
	  private String state;
	  private String country;
	  private SubjectAlternativeNamesByType subjectAlternativeNamesByType;
  }
  
  @Data
  public static class SubjectAlternativeNamesByType {
	  private String[] dnsNames;
  }
}
