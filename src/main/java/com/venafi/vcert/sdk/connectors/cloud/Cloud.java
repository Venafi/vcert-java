package com.venafi.vcert.sdk.connectors.cloud;


import static java.util.Collections.singletonList;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.certificate.CertificateStatus;
import com.venafi.vcert.sdk.certificate.ManagedCertificate;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.connectors.cloud.domain.Project;
import com.venafi.vcert.sdk.connectors.cloud.domain.ProjectZone;
import com.venafi.vcert.sdk.connectors.cloud.domain.Projects;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.utils.FeignUtils;

public interface Cloud {
  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /useraccounts")
  UserDetails authorize(@Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /projectzones/{zoneId}")
  ProjectZone zoneById(@Param("zoneId") String zoneId, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /projectzones/{zone}")
  ProjectZone zones(@Param("zone") String zone, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /devopsprojects?zoneDetails=true")
  Projects projects(@Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /devopsprojects/{projectId}?zoneDetails=true")
  Project projectById(@Param("projectId") String projectId, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /certificateissuingtemplates/{certificateIssuingTemplateId}")
  CertificateIssuingTemplate certificateIssuingTemplateById(
      @Param("certificateIssuingTemplateId") String certificateIssuingTemplateId,
      @Param("apiKey") String apiKey);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json", "Accept: application/json"})
  @RequestLine("POST /certificatesearch")
  CertificateSearchResponse searchCertificates(@Param("apiKey") String apiKey,
      SearchRequest searchRequest);

  @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
  @RequestLine("POST /certificaterequests")
  CloudConnector.CertificateRequestsResponse certificateRequest(@Param("apiKey") String apiKey,
      CloudConnector.CertificateRequestsPayload csr);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /certificaterequests/{id}")
  CertificateStatus certificateStatus(@Param("id") String id, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /certificaterequests/{id}/certificate?chainOrder={chainOrder}&format=PEM")
  Response certificateViaCSR(@Param("id") String id, @Param("apiKey") String apiKey,
      @Param("chainOrder") String chainOrder);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /certificates/{id}/encoded")
  String certificateAsPem(@Param("id") String id, @Param("apiKey") String apiKey);

  @Headers("tppl-api-key: {apiKey}")
  @RequestLine("GET /managedcertificates/{id}")
  ManagedCertificate managedCertificate(@Param("id") String id, @Param("apiKey") String apiKey);

  @RequestLine("GET ping")
  @Headers("x-venafi-api-key: {apiKey}")
  Response ping(@Param("apiKey") String apiKey);

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

    Pattern pattern = Pattern.compile("/v\\d/$");
    Matcher matcher = pattern.matcher(url);
    if (!matcher.find()) {
      // Use API version 1 if not specified
      url = url + "v1/";
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
