package com.venafi.vcert.sdk.connectors.cloud;


import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

public interface Cloud {
    @Headers("tppl-api-key: {apiKey}")
    @RequestLine("GET /useraccounts")
    UserDetails authorize(@Param("apiKey") String apiKey);

    static Cloud connect(String baseUrl) {
        return FeignUtils.client(Cloud.class, baseUrl);
    }
}
