package com.venafi.vcert.sdk.connectors.tpp;


import java.util.List;
import java.util.Map;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.*;

import feign.Headers;
import feign.Param;
import feign.QueryMap;
import feign.RequestLine;
import feign.Response;
import lombok.Data;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.utils.FeignUtils;


public interface Tpp {

  @RequestLine("POST authorize/")
  @Headers("Content-Type: application/json")
  AuthorizeResponse authorize(TppConnector.AuthorizeRequest authorizeRequest);

  @RequestLine("POST certificates/checkpolicy")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(
      TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("value") String value);

  @RequestLine("POST certificates/request")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  CertificateRequestResponse requestCertificate(TppConnector.CertificateRequestsPayload payload, @Param("value") String value);

  @RequestLine("GET certificates/")
  @Headers("x-venafi-api-key: {value}")
  Tpp.CertificateSearchResponse searchCertificates(@QueryMap Map<String, String> query, @Param("value") String value);

  @RequestLine("POST certificates/retrieve")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  CertificateRetrieveResponse certificateRetrieve(
      TppConnector.CertificateRetrieveRequest certificateRetrieveRequest, @Param("value") String value);

  @RequestLine("POST certificates/revoke")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  Tpp.CertificateRevokeResponse revokeCertificate(TppConnector.CertificateRevokeRequest request, @Param("value") String value);


  @RequestLine("POST certificates/renew")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  Tpp.CertificateRenewalResponse renewCertificate(TppConnector.CertificateRenewalRequest request, @Param("value") String value);


  @RequestLine("POST certificates/import")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {value}"})
  ImportResponse importCertificate(ImportRequest request, @Param("value") String value);

  @RequestLine("GET /")
  @Headers("x-venafi-api-key: {value}")
  Response ping(@Param("value") String value);

  @RequestLine("POST Config/IsValid")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  DNIsValidResponse dnIsValid(DNIsValidRequest request, @Param("apiKey") String apiKey);

  @RequestLine("POST Config/Create")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  CreateDNResponse createDN(CreateDNRequest request, @Param("apiKey") String apiKey);

  @RequestLine("POST Config/WritePolicy")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request, @Param("apiKey") String apiKey);

  @RequestLine("POST Config/ReadPolicy")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request, @Param("apiKey") String apiKey);

  @RequestLine("POST Certificates/CheckPolicy")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  GetPolicyResponse getPolicy(GetPolicyRequest request, @Param("apiKey") String apiKey);

  @RequestLine("POST Config/ClearPolicyAttribute")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  Response clearPolicyAttribute(ClearPolicyAttributeRequest request, @Param("apiKey") String apiKey);
  
  @RequestLine("POST SSHCertificates/request")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request, @Param("apiKey") String apiKey);
  
  @RequestLine("POST SSHCertificates/retrieve")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request, @Param("apiKey") String apiKey);
  
  @RequestLine("GET SSHCertificates/Template/Retrieve/PublicKeyData")
  @Headers({"Content-Type: text/plain"})
  Response retrieveSshCAPublicKeyData(@QueryMap Map<String, String> params);
  
  @RequestLine("POST SSHCertificates/Template/Retrieve")
  @Headers({"Content-Type: application/json", "X-Venafi-Api-Key: {apiKey}"})
  TppSshCaTemplateResponse retrieveSshCATemplate(TppSshCaTemplateRequest request, @Param("apiKey") String apiKey);

  //============================Authorization Token Specific operations============================\\

  @RequestLine("POST /vedauth/authorize/oauth")
  @Headers("Content-Type: application/json")
  AuthorizeTokenResponse authorizeToken(AbstractTppConnector.AuthorizeTokenRequest authorizeRequest);

  @RequestLine("POST /vedauth/authorize/token")
  @Headers("Content-Type: application/json")
  RefreshTokenResponse refreshToken(AbstractTppConnector.RefreshTokenRequest request);

  @RequestLine("GET /vedauth/revoke/token")
  @Headers("Authorization: {token}")
  Response revokeToken(@Param("token") String token);

  @RequestLine("POST /vedsdk/certificates/checkpolicy")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  TppConnector.ReadZoneConfigurationResponse readZoneConfigurationToken(
          TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("value") String value);

  @RequestLine("POST /vedsdk/certificates/request")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  CertificateRequestResponse requestCertificateToken(TppConnector.CertificateRequestsPayload payload, @Param("value") String value);

  @RequestLine("GET /vedsdk/certificates/")
  @Headers("Authorization: {value}")
  Tpp.CertificateSearchResponse searchCertificatesToken(@QueryMap Map<String, String> query, @Param("value") String value);

  @RequestLine("POST /vedsdk/certificates/retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  CertificateRetrieveResponse certificateRetrieveToken(
          TppConnector.CertificateRetrieveRequest certificateRetrieveRequest, @Param("value") String value);

  @RequestLine("POST /vedsdk/certificates/revoke")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  Tpp.CertificateRevokeResponse revokeCertificateToken(TppConnector.CertificateRevokeRequest request, @Param("value") String value);


  @RequestLine("POST /vedsdk/certificates/renew")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  Tpp.CertificateRenewalResponse renewCertificateToken(TppConnector.CertificateRenewalRequest request, @Param("value") String value);


  @RequestLine("POST /vedsdk/certificates/import")
  @Headers({"Content-Type: application/json", "Authorization: {value}"})
  ImportResponse importCertificateToken(ImportRequest request, @Param("value") String value);

  @RequestLine("GET /vedsdk")
  @Headers("Authorization: {value}")
  Response pingToken(@Param("value") String value);

  @RequestLine("POST /vedsdk/Config/IsValid")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  DNIsValidResponse dnIsValidToken(DNIsValidRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/Create")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  CreateDNResponse createDNToken(CreateDNRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/WritePolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  SetPolicyAttributeResponse setPolicyAttributeToken(SetPolicyAttributeRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/ReadPolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  GetPolicyAttributeResponse getPolicyAttributeToken(GetPolicyAttributeRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Certificates/CheckPolicy")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  GetPolicyResponse getPolicyToken(GetPolicyRequest request, @Param("token") String token);

  @RequestLine("POST /vedsdk/Config/ClearPolicyAttribute")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  Response clearPolicyAttributeToken(ClearPolicyAttributeRequest request, @Param("token") String token);
  
  @RequestLine("POST /vedsdk/SSHCertificates/request")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCertRequestResponse requestSshCertificateToken(TppSshCertRequest request, @Param("token") String token);
  
  @RequestLine("POST /vedsdk/SSHCertificates/retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCertRetrieveResponse retrieveSshCertificateToken(TppSshCertRetrieveRequest request, @Param("token") String token);
  
  @RequestLine("GET /vedsdk/SSHCertificates/Template/Retrieve/PublicKeyData")
  @Headers({"Content-Type: text/plain"})
  Response retrieveSshCAPublicKeyDataToken(@QueryMap Map<String, String> params);
  
  @RequestLine("POST vedsdk/SSHCertificates/Template/Retrieve")
  @Headers({"Content-Type: application/json", "Authorization: {token}"})
  TppSshCaTemplateResponse retrieveSshCATemplateToken(TppSshCaTemplateRequest request, @Param("token") String token);

  //=================================================================================================\

  static Tpp connect(String baseUrl) {
    return FeignUtils.client(Tpp.class, Config.builder().baseUrl(baseUrl).build());
  }

  static Tpp connect(Config config) {
    return FeignUtils.client(Tpp.class, config);
  }

  @Data
  class CertificateSearchResponse {
    private Integer count;
    private List<Certificate> certificates;
  }

  @Data
  class Certificate {
    @SerializedName("DN")
    private String certificateRequestId;
  }

  @Data
  class CertificateRequestResponse {
    @SerializedName("CertificateDN")
    private String certificateDN;
    @SerializedName("Guid")
    private String guid;
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
  class CertificateRenewalResponse {
    private boolean success;
    private String error;
  }

  @Data
  class CertificateRevokeResponse {
    private boolean requested;
    private boolean success;
    private String error;
  }
}
