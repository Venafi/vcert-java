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
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.utils.FeignUtils;


public interface Tpp {

  @RequestLine("POST authorize/")
  @Headers("Content-Type: application/json")
  AuthorizeResponse authorize(TppConnector.AuthorizeRequest authorizeRequest);

  @RequestLine("POST certificates/checkpolicy")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(
      TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest,
      @Param("apiKey") String apiKey);

  @RequestLine("POST certificates/request")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  CertificateRequestResponse requestCertificate(TppConnector.CertificateRequestsPayload payload,
      @Param("apiKey") String apiKey);

  @RequestLine("GET certificates/")
  @Headers("x-venafi-api-key: {apiKey}")
  Tpp.CertificateSearchResponse searchCertificates(@QueryMap Map<String, String> query,
      @Param("apiKey") String apiKey);

  @RequestLine("POST certificates/retrieve")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  CertificateRetrieveResponse certificateRetrieve(
      TppConnector.CertificateRetrieveRequest certificateRetrieveRequest,
      @Param("apiKey") String apiKey);

  @RequestLine("POST certificates/revoke")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  Tpp.CertificateRevokeResponse revokeCertificate(TppConnector.CertificateRevokeRequest request,
      @Param("apiKey") String apiKey);


  @RequestLine("POST certificates/renew")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  Tpp.CertificateRenewalResponse renewCertificate(TppConnector.CertificateRenewalRequest request,
      @Param("apiKey") String apiKey);


  @RequestLine("POST certificates/import")
  @Headers({"Content-Type: application/json", "x-venafi-api-key: {apiKey}"})
  ImportResponse importCertificate(ImportRequest request, @Param("apiKey") String apiKey);

  @RequestLine("GET /")
  @Headers("x-venafi-api-key: {apiKey}")
  Response ping(@Param("apiKey") String apiKey);

  static Tpp connect(String baseUrl) {
    return FeignUtils.client(Tpp.class, baseUrl);
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
