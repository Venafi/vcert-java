package com.venafi.vcert.sdk.connectors.tpp;


import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.Param;
import feign.RequestLine;


public interface Tpp {

    @RequestLine("POST authorize/")
    @Headers("Content-Type: application/json")
    AuthorizeResponse authorize(TppConnector.AuthorizeRequest authorizeRequest);

    @RequestLine("POST certificates/checkpolicy")
    @Headers({
            "Content-Type: application/json",
            "x-venafi-api-key: {apiKey}"
    })
    TppConnector.ReadZoneConfigurationResponse readZoneConfiguration(TppConnector.ReadZoneConfigurationRequest readZoneConfigurationRequest, @Param("apiKey") String apiKey);

    static Tpp connect(String baseUrl) {
        return FeignUtils.client(Tpp.class, baseUrl);
    }

}