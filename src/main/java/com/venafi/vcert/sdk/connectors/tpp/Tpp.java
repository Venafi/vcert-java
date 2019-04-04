package com.venafi.vcert.sdk.connectors.tpp;


import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import lombok.Data;

import java.util.List;


public interface Tpp {

    static Tpp connect(String baseUrl) {
        return FeignUtils.client(Tpp.class, baseUrl);
    }

    @RequestLine("POST authorize/")
    @Headers("Content-Type: application/json")
    AuthorizeResponse authorize(TppConnector.AuthorizeRequest authorizeRequest);

    @RequestLine("POST certificates/checkpolicy")
    @Headers({
            "Content-Type: application/json",
            "x-venafi-api-key: {apiKey}"
    })
    TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("apiKey") String apiKey);

    @RequestLine("POST certificates/request")
    @Headers("Content-Type: application/json")
    String requestCertificate(TppConnector.CertificateRequestsPayload payload, @Param("apiKey") String apiKey);

    @RequestLine("GET certificates/?{search}")
    @Headers("x-venafi-api-key: {apiKey}")
    Tpp.CertificateSearchResponse searchCertificates(@Param("search") String searchRequest, @Param("apiKey") String apiKey);

    @RequestLine("POST certificates/retrieve")
    @Headers({
            "Content-Type: application/json",
            "x-venafi-api-key: {apiKey}"
    })
    TppConnector.CertificateRetrieveResponse certificateRetrieve(TppConnector.CertificateRetrieveRequest certificateRetrieveRequest, @Param("apiKey") String apiKey);

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
        private String id;
        private String managedCertificateId;
        private String certificateRequestId;
        private List<String> subjectCN;
    }

}