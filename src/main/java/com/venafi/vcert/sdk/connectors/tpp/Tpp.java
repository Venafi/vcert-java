package com.venafi.vcert.sdk.connectors.tpp;


import com.venafi.vcert.sdk.utils.FeignUtils;
import feign.Headers;
import feign.RequestLine;


public interface Tpp {

    @RequestLine("POST authorize/")
    @Headers("Content-Type: application/json")
    AuthorizeResponse authorize(TppConnector.AuthorizeRequest authorizeRequest);

    static Tpp connect(String baseUrl) {
        return FeignUtils.client(Tpp.class, baseUrl);
    }

}