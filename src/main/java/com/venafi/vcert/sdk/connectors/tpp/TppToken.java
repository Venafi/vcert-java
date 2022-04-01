package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.*;
import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.*;

import java.util.Map;

public interface TppToken extends Tpp{

  @RequestLine("POST /vedauth/authorize/oauth")
  @Headers("Content-Type: application/json")
  AuthorizeTokenResponse authorizeToken(AbstractTppConnector.AuthorizeTokenRequest authorizeRequest);

  @RequestLine("GET /vedauth/authorize/verify")
  @Headers({"Authorization: {token}"})
  VerifyTokenResponse verifyToken(@Param("token") String token);

  @RequestLine("POST /vedauth/authorize/token")
  @Headers("Content-Type: application/json")
  RefreshTokenResponse refreshToken(AbstractTppConnector.RefreshTokenRequest request);

  @RequestLine("GET /vedauth/revoke/token")
  @Headers("Authorization: {token}")
  Response revokeToken(@Param("token") String token);

  @RequestLine("POST /vedsdk/certificates/checkpolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(
      TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("token") String token);

  @RequestLine("POST /vedsdk/certificates/request")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  CertificateRequestResponse requestCertificate(TppConnector.CertificateRequestsPayload payload,
      @Param("token") String token);

  @RequestLine("GET /vedsdk/certificates/")
  @Headers("Authorization: {token}")
  Tpp.CertificateSearchResponse searchCertificates(@QueryMap Map<String, String> query, @Param("token") String token);

  @RequestLine("POST /vedsdk/certificates/retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  CertificateRetrieveResponse certificateRetrieve(
      TppConnector.CertificateRetrieveRequest certificateRetrieveRequest, @Param("token") String token);

  @RequestLine("POST /vedsdk/certificates/revoke")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  Tpp.CertificateRevokeResponse revokeCertificate(TppConnector.CertificateRevokeRequest request,
      @Param("token") String token);


  @RequestLine("POST /vedsdk/certificates/renew")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  Tpp.CertificateRenewalResponse renewCertificate(TppConnector.CertificateRenewalRequest request,
      @Param("token") String token);


  @RequestLine("POST /vedsdk/certificates/import")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  ImportResponse importCertificate(ImportRequest request, @Param("token") String token);

  @RequestLine("GET /vedsdk")
  @Headers("Authorization: {token}")
  Response ping(@Param("token") String token);

  @RequestLine("POST /vedsdk/Config/IsValid")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  DNIsValidResponse dnIsValid(DNIsValidRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/Create")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  CreateDNResponse createDN(CreateDNRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/WritePolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/ReadPolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Certificates/CheckPolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  GetPolicyResponse getPolicy(GetPolicyRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/ClearPolicyAttribute")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  Response clearPolicyAttribute(ClearPolicyAttributeRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Identity/Browse")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  BrowseIdentitiesResponse browseIdentities(BrowseIdentitiesRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Identity/Validate")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  ValidateIdentityResponse validateIdentity(ValidateIdentityRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/SSHCertificates/request")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/SSHCertificates/retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request, @Param("token") String token);

  @RequestLine("GET /vedsdk/SSHCertificates/Template/Retrieve/PublicKeyData")
  @Headers({"Content-Type: text/plain"})
  Response retrieveSshCAPublicKeyData(@QueryMap Map<String, String> params);

  @RequestLine("POST vedsdk/SSHCertificates/Template/Retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCaTemplateResponse retrieveSshCATemplate(TppSshCaTemplateRequest request, @Param("token") String token);

  static Tpp connect(String baseUrl) {
    return FeignUtils.client(TppToken.class, Config.builder().baseUrl(baseUrl).build());
  }

  static Tpp connect(Config config) {
    return FeignUtils.client(TppToken.class, config);
  }
}
