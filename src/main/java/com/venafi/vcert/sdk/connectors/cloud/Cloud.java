package com.venafi.vcert.sdk.connectors.cloud;


import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

public interface Cloud {
    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/useraccounts")
    UserDetails authorize(@Param("apiKey") String apiKey);

    static Cloud connect(String baseUrl) {
        return FeignUtils.client(Cloud.class, baseUrl);
    }

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/zones/tag/{zone}")
    Zone zoneByTag(@Param("zone") String zone, @Param("apiKey") String apiKey);

    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /v1/certificatepolicies/{id}")
    CertificatePolicy policyById(@Param("id") String id, @Param("apiKey") String apiKey);

    @Headers({"tppl-api-key: {apiKey}", "Content-Type: application/json"})
    @RequestLine("POST /v1/useraccounts")
    UserDetails register(@Param("apiKey") String apiKey, UserAccount userAccount);

}
