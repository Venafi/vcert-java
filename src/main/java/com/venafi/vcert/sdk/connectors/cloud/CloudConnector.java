package com.venafi.vcert.sdk.connectors.cloud;

import static com.venafi.vcert.sdk.connectors.cloud.CloudConnectorException.*;
import static java.lang.String.format;
import static java.time.Duration.ZERO;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

import java.io.IOException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.venafi.vcert.sdk.connectors.cloud.domain.*;
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
import com.venafi.vcert.sdk.certificate.ChainOption;
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
      throw new UnexpectedStatusException( response.status(), response.reason());
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
	    zoneConfig.zoneId(zoneId);
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

    if (CsrOriginOption.ServiceGeneratedCSR == request.csrOrigin()) {
      throw new UnsupportedServiceGeneratedCSRException();
    }
    if (user == null || user.company() == null) {
      throw new UserNotAuthenticatedException("Must be authenticated to request a certificate");
    }
    
    CertificateRequestsPayload payload = new CertificateRequestsPayload()
    .zoneId(zoneConfiguration.zoneId()).csr(new String(request.csr()));
    
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

    
    CertificateRequestsResponse response =
        cloud.certificateRequest( auth.apiKey(), payload );

    String requestId = response.certificateRequests().get(0).id();
    request.pickupId(requestId);
    return requestId;
  }

  @Override
  public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
	  CertificateStatus certificateStatus = null;
    if (request.fetchPrivateKey()) {
      throw new UnsupportedPrivateKeyRetrieveException();
    }
    String certId = "";
    if (isBlank(request.pickupId()) && isNotBlank(request.thumbprint())) {
      String certificateRequestId = null;
      Cloud.CertificateSearchResponse certificateSearchResponse =
          searchCertificatesByFingerprint(request.thumbprint());
      if (certificateSearchResponse.certificates().size() == 0) {
        throw new CertificateNotFoundByFingerprintException(request.thumbprint());
      }

      List<String> reqIds = new ArrayList<>();
      boolean isOnlyOneCertificateRequestId = true;
      for (Cloud.Certificate certificate : certificateSearchResponse.certificates()) {
        reqIds.add(certificate.certificateRequestId());
        if (isNotBlank(certificateRequestId)
            && certificateRequestId.equals(certificate.certificateRequestId())) {
          isOnlyOneCertificateRequestId = false;
        }
        if (isNotBlank(certificate.certificateRequestId())) {
          certificateRequestId = certificate.certificateRequestId();
        } else {
          certId = certificate.id();
        }
      }
      if (!isOnlyOneCertificateRequestId) {
        throw new MoreThanOneCertificateRequestIdException(reqIds);
      }
      request.pickupId(certificateRequestId);
    }

    // TODO move this retry logic to feign client
    Instant startTime = Instant.now();
    while (true) {
      if (isBlank(request.pickupId())) {
        break;
      }

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
    
    String certificateId = certificateStatus.certificateIds().get(0);

    if (isNotBlank(certificateId)) {

      // Todo cleanup unnecessary switch
      String chainOption;
      switch (request.chainOption()) {
        case ChainOptionRootFirst:
          chainOption = "ROOT_FIRST";
          break;
        case ChainOptionRootLast:
        case ChainOptionIgnore:
        default:
          chainOption = "EE_FIRST";
          break;
      }
      String body = certificateViaCSR(certificateId, chainOption, request);
      PEMCollection pemCollection =
          PEMCollection.fromResponse(body, request.chainOption(), request.privateKey(),
            request.keyPassword());
      request.checkCertificate(pemCollection.certificate());
      return pemCollection;
    } else {
      String body = certificateAsPem(certId, request);
      return PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore,
        request.privateKey(), request.keyPassword());
    }
  }

  private String certificateViaCSR(String certificateId, String chainOrder, CertificateRequest request) throws VCertException {
	  // We should decode this as is not REST, multiple decoders should be supported
	  // by feign as a potential improvement.
	  Instant startTime = Instant.now();
	  while (true) {

		  Response response = cloud.certificateViaCSR(certificateId, auth.apiKey(), chainOrder);
		  if (response.status() == 200) {
			  try {
				  return CharStreams.toString(response.body().asReader());
			  } catch (IOException e) {
				  throw new UnableToReadPEMCertificateException(certificateId);
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
  }

  private String certificateAsPem(String certificateId, CertificateRequest request) throws VCertException{
	  
	  Instant startTime = Instant.now();
	  while (true) {

		  Response response = cloud.certificateAsPem(certificateId, auth.apiKey());
		  if (response.status() == 200) {
			  try {
				  return CharStreams.toString(response.body().asReader());
			  } catch (IOException e) {
				  throw new UnableToReadPEMCertificateException(certificateId);
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
        throw new CertificateNotFoundByFingerprintException(request.thumbprint());
      }

      certificateRequestId = requestIds.iterator().next();

    } else if (isNotBlank(request.certificateDN())) {
      certificateRequestId = request.certificateDN();
    } else {
      throw new CertificateDNOrFingerprintWasNotProvidedException();
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
    PolicySpecification policySpecification;
    try {
      CloudPolicy cloudPolicy = CloudConnectorUtils.getCloudPolicy( policyName, auth.apiKey(), cloud );
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
}
