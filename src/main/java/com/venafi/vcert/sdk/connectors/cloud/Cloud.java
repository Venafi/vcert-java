package com.venafi.vcert.sdk.connectors.cloud;


import com.venafi.vcert.sdk.certificate.CertificateStatus;
import com.venafi.vcert.sdk.certificate.ManagedCertificate;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

import static java.util.Collections.singletonList;

public interface Cloud {
    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/useraccounts")
    UserDetails authorize(@Param("apiKey") String apiKey);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/zones/tag/{zone}")
    Zone zoneByTag(@Param("zone") String zone, @Param("apiKey") String apiKey);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/certificatepolicies/{id}")
    CertificatePolicy policyById(@Param("id") String id, @Param("apiKey") String apiKey);

    @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
    @RequestLine("POST /v1/useraccounts")
    UserDetails register(@Param("apiKey") String apiKey, UserAccount userAccount);

    @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
    @RequestLine("POST /v1/certificatesearch")
    CertificateSearchResponse searchCertificates(@Param("apiKey") String apiKey, SearchRequest searchRequest);

    @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
    @RequestLine("POST /v1/certificaterequests")
    CloudConnector.CertificateRequestsResponse certificateRequest(@Param("apiKey") String apiKey, CloudConnector.CertificateRequestsPayload csr);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/certificaterequests/{id}")
    CertificateStatus certificateStatus(@Param("id") String id, @Param("apiKey") String apiKey);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/certificaterequests/{id}/certificate?chainOrder={chainOrder}&format=PEM")
    String certificateViaCSR(@Param("id") String id, @Param("apiKey") String apiKey, @Param("chainOrder") String chainOrder);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/certificates/{id}/encoded")
    String certificateAsPem(@Param("id") String id, @Param("apiKey") String apiKey);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/managedcertificates/{id}")
    ManagedCertificate managedCertificate(@Param("id") String id, @Param("apiKey") String apiKey);

    @RequestLine("GET ping")
    @Headers("x-venafi-api-key: {apiKey}")
    Response ping(@Param("apiKey") String apiKey);

    static Cloud connect(String baseUrl) {
        return FeignUtils.client(Cloud.class, baseUrl);
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
            return new SearchRequest(
                    new Cloud.Expression(singletonList(
                            new Cloud.Operand("fingerprint", "MATCH", fingerprint))));
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
