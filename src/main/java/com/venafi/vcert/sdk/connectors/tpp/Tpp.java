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
  
  @RequestLine("POST vedauth/authorize/OAuth")
  @Headers("Content-Type: application/json")
  AuthorizeResponseV2 authorize(TppConnector.AuthorizeRequestV2 authorizeRequest);
  
  @RequestLine("POST vedauth/authorize/token")
  @Headers("Content-Type: application/json")
  ResfreshTokenResponse refreshToken(TppConnector.RefreshTokenRequest request);
  
  @RequestLine("GET vedauth/revoke/token")
  @Headers("Authorization: {token}")
  Response revokeToken(@Param("token") String token);

  @RequestLine("POST certificates/checkpolicy")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(
      TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("header") String header,
      @Param("value") String value);

  @RequestLine("POST certificates/request")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  CertificateRequestResponse requestCertificate(TppConnector.CertificateRequestsPayload payload, @Param("header") String header,
      @Param("value") String value);

  @RequestLine("GET certificates/")
  @Headers("{header}: {value}")
  Tpp.CertificateSearchResponse searchCertificates(@QueryMap Map<String, String> query, @Param("header") String header,
      @Param("value") String value);

  @RequestLine("POST certificates/retrieve")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  CertificateRetrieveResponse certificateRetrieve(
      TppConnector.CertificateRetrieveRequest certificateRetrieveRequest, @Param("header") String header,
      @Param("value") String value);

  @RequestLine("POST certificates/revoke")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  Tpp.CertificateRevokeResponse revokeCertificate(TppConnector.CertificateRevokeRequest request, @Param("header") String header,
      @Param("value") String value);


  @RequestLine("POST certificates/renew")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  Tpp.CertificateRenewalResponse renewCertificate(TppConnector.CertificateRenewalRequest request, @Param("header") String header,
      @Param("value") String value);


  @RequestLine("POST certificates/import")
  @Headers({"Content-Type: application/json", "{header}: {value}"})
  ImportResponse importCertificate(ImportRequest request, @Param("header") String header, @Param("value") String value);

  @RequestLine("GET /")
  @Headers("{header}: {value}")
  Response ping(@Param("header") String header, @Param("value") String value);

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
