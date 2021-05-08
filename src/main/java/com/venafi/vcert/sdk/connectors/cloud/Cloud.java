package com.venafi.vcert.sdk.connectors.cloud;

import static java.util.Collections.singletonList;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.certificate.CertificateStatus;
import com.venafi.vcert.sdk.connectors.cloud.domain.Application;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateDetails;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.cloud.endpoint.*;
import com.venafi.vcert.sdk.utils.FeignUtils;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public interface Cloud {
  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET v1/useraccounts")
  UserDetails authorize(@Param("apiKey") String apiKey);
  
  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /outagedetection/v1/applications/{appName}/certificateissuingtemplates/{citAlias}")
  CertificateIssuingTemplate certificateIssuingTemplateByAppNameAndCitAlias(
	  @Param("appName") String appName,
      @Param("citAlias") String citAlias,
      @Param("apiKey") String apiKey);
  
  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /outagedetection/v1/applications/name/{appName}")
  Application applicationByName(
	  @Param("appName") String appName,
      @Param("apiKey") String apiKey);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json", "Accept: application/json"})
  @RequestLine("POST /outagedetection/v1/certificatesearch")
  CertificateSearchResponse searchCertificates(@Param("apiKey") String apiKey,
      SearchRequest searchRequest);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  @RequestLine("POST  /outagedetection/v1/certificaterequests")
  CloudConnector.CertificateRequestsResponse certificateRequest(@Param("apiKey") String apiKey,
      CloudConnector.CertificateRequestsPayload csr);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET  /outagedetection/v1/certificaterequests/{id}")
  CertificateStatus certificateStatus(@Param("id") String id, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /outagedetection/v1/certificates/{id}/contents?chainOrder={chainOrder}&format=PEM")
  Response certificateViaCSR(@Param("id") String id, @Param("apiKey") String apiKey,
      @Param("chainOrder") String chainOrder);

  @Headers({"tppl-api-key: {apiKey}"})
  @RequestLine("GET /outagedetection/v1/certificates/{id}/contents")
  Response certificateAsPem(@Param("id") String id, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /outagedetection/v1/certificates/{id}")
  CertificateDetails certificateDetails(@Param("id") String id, @Param("apiKey") String apiKey);

  @RequestLine("GET ping")
  @Headers("x-venafi-api-key: {apiKey}")
  Response ping(@Param("apiKey") String apiKey);

  @RequestLine("GET /v1/certificateauthorities/{CA}/accounts")
  @Headers("tppl-api-key: {apiKey}")
  CAAccountsList getCAAccounts(@Param("CA") String caName, @Param("apiKey") String apiKey);

  @RequestLine("GET /v1/certificateauthorities/{CA}/accounts/{id}")
  @Headers("tppl-api-key: {apiKey}")
  //CAAccountResponse getCAAccount(@Param("CA") String caName, @Param("id") String id, @Param("apiKey") String apiKey);
  CAAccount getCAAccount(@Param("CA") String caName, @Param("id") String id, @Param("apiKey") String apiKey);

  @RequestLine("GET /v1/certificateissuingtemplates")
  @Headers("tppl-api-key: {apiKey}")
  CITsList getCITs(@Param("apiKey") String apiKey);

  @RequestLine("POST /v1/certificateissuingtemplates")
  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  CITsList createCIT(CertificateIssuingTemplate cit, @Param("apiKey") String apiKey);

  /*@RequestLine("POST /v1/certificateissuingtemplates")
  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  CITsList createCIT(EntrustCIT cit, @Param("apiKey") String apiKey);*/

  @RequestLine("PUT /v1/certificateissuingtemplates/{id}")
  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  CertificateIssuingTemplate updateCIT(CertificateIssuingTemplate cit, @Param("id") String id, @Param("apiKey") String apiKey);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  @RequestLine("POST /outagedetection/v1/applications")
  ApplicationsList createApplication(Application application, @Param("apiKey") String apiKey);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  @RequestLine("PUT /outagedetection/v1/applications/{id}")
  Application updateApplication(Application application, @Param("id") String id, @Param("apiKey") String apiKey);

  static Cloud connect(String baseUrl) {
    return FeignUtils.client(Cloud.class, 
        Config.builder().baseUrl(
          normalizeUrl(isNotBlank(baseUrl) ? baseUrl : "https://api.venafi.cloud")).build());
  }

  static Cloud connect(Config config) {
    config.baseUrl(
        normalizeUrl(isNotBlank(config.baseUrl()) ? config.baseUrl() : "https://api.venafi.cloud"));

    return FeignUtils.client(Cloud.class, config);
  }

  static String normalizeUrl(String url) {
    url = url.toLowerCase();

    Pattern patternProtocol = Pattern.compile("^http(|s)://");
    Matcher matcherProtocol = patternProtocol.matcher(url);
    if (!matcherProtocol.find()) {
      // Add HTTPS if no protocol is specified
      url = "https://" + url;
    }

    if (!url.endsWith("/")) {
      // Add trailing slash
      url = url + "/";
    }

    
    return url;
  }

  @Data
  @NoArgsConstructor
  class SearchRequest {
    private Expression expression;
    private Object ordering;
    private Paging paging;

    SearchRequest(Expression expression) {
      this.expression = expression;
    }

    static SearchRequest findByFingerPrint(String fingerprint) {
      return new SearchRequest(new Cloud.Expression(
          singletonList(new Cloud.Operand("fingerprint", "MATCH", fingerprint))));
    }
  }

  @Data
  @AllArgsConstructor
  class Expression {
    private List<Operand> operands;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  class Operand {
    private String field;
    private String operator;
    private Object value;
  }

  @Data
  class Paging {
    private Integer pageNumber;
    private Integer pageSize;
  }

  @Data
  class CertificateSearchResponse {
    private Integer count;
    private List<Certificate> certificates;
  }

  @Data
  class Certificate {
    private String id;
    private String managedCertificateId;
    private String certificateRequestId;
    private List<String> subjectCN;
  }
}
