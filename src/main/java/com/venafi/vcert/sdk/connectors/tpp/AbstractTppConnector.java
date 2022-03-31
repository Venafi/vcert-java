package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.SshCaTemplateRequest;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.certificate.SshConfig;
import com.venafi.vcert.sdk.connectors.ConnectorException.*;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.BrowseIdentitiesResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.BrowseIdentitiesRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.IdentityEntry;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.*;
import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.time.Duration.ZERO;

public abstract class AbstractTppConnector {
  protected static final String HEADER_VALUE_AUTHORIZATION = "Bearer %s";

  protected static final String FAILED_TO_AUTHENTICATE_MESSAGE = "failed to authenticate: ";
  protected static final String MISSING_CREDENTIALS_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing credentials";
  protected static final String MISSING_REFRESH_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing refresh token";
  protected static final String MISSING_ACCESS_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing access token";
  protected static final String TPP_ATTRIBUTE_MANAGEMENT_TYPE = "Management Type";
  protected static final String TPP_ATTRIBUTE_MANUAL_CSR = "Manual Csr";
  protected static final String LEGACY_DATA_FORMAT = "base64";
  protected static final String PKCS8_DATA_FORMAT = "base64 (PKCS #8)";

  // TODO can be enum
  @SuppressWarnings("serial")
  protected static final Map<String, Integer> revocationReasons = new HashMap<>();
  static {
    revocationReasons.put("", 0); // NoReason
    revocationReasons.put("none", 0); //
    revocationReasons.put("key-compromise", 1); // UserKeyCompromised
    revocationReasons.put("ca-compromise", 2); // CAKeyCompromised
    revocationReasons.put("affiliation-changed", 3); // UserChangedAffiliation
    revocationReasons.put("superseded", 4); // CertificateSuperseded
    revocationReasons.put("cessation-of-operation", 5); // OriginalUseNoLongerValid
  }

  protected final Tpp tpp;

  @Getter
  protected String zone;
  protected String vendorAndProductName;

  protected TppAPI tppAPI;

  public AbstractTppConnector(Tpp tpp) {
    this.tpp = tpp;
    this.tppAPI = getTppAPI();
  }

  protected abstract TppAPI getTppAPI();

  @VisibleForTesting
  String getPolicyDN(final String zone) {
    String result = zone;

    result = result.startsWith("\\") ? result : "\\"+result;//Ensuring that the zone starts with a "\"
    result = result.startsWith("\\VED\\Policy") ? result : "\\VED\\Policy"+result; //Ensuring that the zone starts with "\VED\Policy"

    return result;
  }

  public void setPolicy(String policyName, TPPPolicy tppPolicy) throws VCertException {

    //ensuring that the policy name starts with the tpp_root_path
    if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
      policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

    tppPolicy.policyName( policyName );

    //if the policy doesn't exist
    if(!TppConnectorUtils.dnExist(policyName, tppAPI)){

      //verifying that the policy's parent exists
      String parentName = tppPolicy.getParentName();
      if(!parentName.equals(TppPolicyConstants.TPP_ROOT_PATH) && !TppConnectorUtils.dnExist(parentName, tppAPI))
        throw new VCertException(String.format("The policy's parent %s doesn't exist", parentName));

      //creating the policy
      TppConnectorUtils.createPolicy( policyName, tppAPI );
    } else
      TppConnectorUtils.resetAttributes(policyName, tppAPI);

    //creating policy's attributes.
    TppConnectorUtils.setPolicyAttributes(tppPolicy, tppAPI);
  }

  public TPPPolicy getTPPPolicy(String policyName) throws VCertException {

    TPPPolicy tppPolicy = new TPPPolicy();

    //ensuring that the policy name starts with the tpp_root_path
    if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
      policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

    tppPolicy.policyName( policyName );

    //populating the tppPolicy
    TppConnectorUtils.populatePolicy(tppPolicy, tppAPI);

    return tppPolicy;
  }

  protected String[] resolveTPPContacts(String[] contacts) throws VCertException{
    List<String> identitiesIdList = new ArrayList<>();
    for (String contact: contacts) {
      IdentityEntry identity = this.getTPPIdentity(contact);
      identitiesIdList.add(identity.prefixedUniversal());
    }
    return identitiesIdList.toArray(new String[0]);
  }

  public IdentityEntry getTPPIdentity(String username) throws VCertException{
    if (username == null){
      throw new VCertException("Identity string cannot be null");
    }

    BrowseIdentitiesResponse response = getTppAPI().browseIdentities(new BrowseIdentitiesRequest(username, 2,
            BrowseIdentitiesRequest.ALL_IDENTITIES));

    if (response.identities().length > 1){
      throw new VCertException("Extraneous information returned in the identity response. "
              + "Expected size: 1, found: 2\n" + response.identities()[1].toString());
    }

    IdentityEntry identity = response.identities()[0];

    return identity;
  }



  protected TppSshCertRequestResponse requestTppSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException {

    TppSshCertRequest tppSshCertRequest = TppConnectorUtils.convertToTppSshCertReq(sshCertificateRequest);

    TppSshCertRequestResponse requestResponse;

    try {
      requestResponse = tppAPI.requestSshCertificate(tppSshCertRequest);
    } catch (Exception e) {
      throw new VCertException(e);
    }

    if( !requestResponse.response().success() )
      throw new RequestCertificateException(requestResponse.response().errorCode(), requestResponse.response().errorMessage());

    return requestResponse;
  }

  protected SshCertRetrieveDetails retrieveTppSshCertificate(SshCertificateRequest sshCertificateRequest)
          throws VCertException {

    TppSshCertRetrieveResponse tppSshCertRetrieveResponse;

    TppSshCertRetrieveRequest tppSshCertRetrieveRequest = TppConnectorUtils.convertToTppSshCertRetReq(sshCertificateRequest);

    // TODO move this retry logic to feign client
    Instant startTime = Instant.now();
    while (true) {
      tppSshCertRetrieveResponse = tppAPI.retrieveSshCertificate(tppSshCertRetrieveRequest);

      //if the certificate was returned(Issued)
      if( StringUtils.isNotBlank(tppSshCertRetrieveResponse.certificateData())) {
        break;
      }

      //if the certificate request was rejected
      if( tppSshCertRetrieveResponse.response().success() && tppSshCertRetrieveResponse.processingDetails().status().equals("Rejected") )
        throw new CertificateRejectedException(sshCertificateRequest.pickupID(), tppSshCertRetrieveResponse.processingDetails().statusDescription());

      //if the certificate is pending to be issued
      if (ZERO.equals(sshCertificateRequest.timeout())) {
        throw new CertificatePendingException(sshCertificateRequest.pickupID(), tppSshCertRetrieveResponse.processingDetails().statusDescription());
      }

      //if the timeout was reached
      if (Instant.now().isAfter(startTime.plus(sshCertificateRequest.timeout()))) {
        throw new RetrieveCertificateTimeoutException(sshCertificateRequest.pickupID());
      }

      try {
        TimeUnit.SECONDS.sleep(2);
      } catch (InterruptedException e) {
        // Restore interrupted state...
        Thread.currentThread().interrupt();
        throw new AttemptToRetryException(e);
      }
    }

    return TppConnectorUtils.convertToSshCertRetrieveDetails(tppSshCertRetrieveResponse);
  }

  protected SshConfig retrieveTppSshConfig(SshCaTemplateRequest sshCaTemplateRequest) throws VCertException {
    SshConfig sshConfig = new SshConfig();

    Map<String, String> params = new HashMap<>();

    if(StringUtils.isNotBlank(sshCaTemplateRequest.template()))
      params.put("DN", TppConnectorUtils.getSshCADN(sshCaTemplateRequest.template()));
    else
    if(StringUtils.isNotBlank(sshCaTemplateRequest.guid()))
      params.put("Guid", sshCaTemplateRequest.guid());
    else
      throw new CAOrGUIDNotProvidedException();

    //TODO confirm if it is required to catch the FeignException and rethrow it as a VcertException
    //TODO determine if it is required to verify that the caPublicKey is not empty
    sshConfig.caPublicKey( tppAPI.retrieveSshCAPublicKeyData(params) );

    sshConfig.principals(retrieveTppSshPrincipals(sshCaTemplateRequest));

    return sshConfig;
  }

  private String[] retrieveTppSshPrincipals( SshCaTemplateRequest sshCaTemplateRequest ) throws VCertException {

    //block of code to confirm if it was provided an authKey(APIKey/Token)
    try {
      tppAPI.getAuthKey();
    } catch (VCertException e) {
      return null;
    }

    TppSshCaTemplateRequest request = new TppSshCaTemplateRequest();

    if(StringUtils.isNotBlank(sshCaTemplateRequest.template()))
      request.dn( TppConnectorUtils.getSshCADN(sshCaTemplateRequest.template()) );
    else
    if(StringUtils.isNotBlank(sshCaTemplateRequest.guid()))
      request.guid( sshCaTemplateRequest.guid() );
    else
      throw new CAOrGUIDNotProvidedException();

    return tppAPI.retrieveSshCATemplate(request).accessControl().defaultPrincipals();
  }


  @Data
  @AllArgsConstructor
  public static class AuthorizeRequest {
    private String username;
    private String password;
  }

  @Data
  @AllArgsConstructor
  static class AuthorizeTokenRequest{

    @SerializedName("username")
    private String username;

    @SerializedName("password")
    private String password;

    @SerializedName("client_id")
    private String clientId;

    @SerializedName("scope")
    private String scope;

    @SerializedName("state")
    private String state;

    @SerializedName("redirect_uri")
    private String redirectUri;

  }

  @Data
  @AllArgsConstructor
  static class RefreshTokenRequest{
    @SerializedName("refresh_token")
    private String refreshToken;
    @SerializedName("client_id")
    private String clientId;
  }

  @Data
  @AllArgsConstructor
  public static class ReadZoneConfigurationRequest {
    String policyDN;
  }

  @Data
  public static class ReadZoneConfigurationResponse {
    Object error;
    ServerPolicy policy;
  }

  @Data
  public static class CertificateRequestsPayload {
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
    @SerializedName("SubjectAltNames")
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
    private String origin;

    @SerializedName("CustomFields")
    private ArrayList<CustomFieldRequest> customFields;
  }

  @Data
  protected static class SANItem {
    private int type;
    private String name;
  }

  @Data
  @AllArgsConstructor
  public static class NameValuePair<K, V> {
    private K name;
    private V value;
  }

  @Data
  public class CertificateRetrieveRequest {
    private String certificateDN;
    private String format;
    private String password;
    private boolean includePrivateKey;
    private boolean includeChain;
    private String friendlyName;
    private boolean rootFirstOrder;
  }

  @Data
  public class CertificateRevokeRequest {
    private String certificateDN;
    private String thumbprint;
    private Integer reason;
    private String comments;
    private boolean disable;
  }

  @Data
  public class CertificateRenewalRequest {
    private String certificateDN;
    private String PKCS10;
  }
}
