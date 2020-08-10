package com.venafi.vcert.sdk.connectors.tpp;


import java.util.List;
import java.util.Map;
import com.google.gson.annotations.SerializedName;
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


  //============================Authorization Token Specific operations============================\\

  @RequestLine("POST /vedauth/authorize/oauth")
  @Headers("Content-Type: application/json")
  AuthorizeTokenResponse authorizeToken(AbstractTppConnector.AuthorizeTokenRequest authorizeRequest);

  @RequestLine("POST /vedauth/authorize/token")
  @Headers("Content-Type: application/json") RefreshTokenResponse refreshToken(AbstractTppConnector.RefreshTokenRequest request);

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

  //===============================================================================================\\

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
