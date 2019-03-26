package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.ZonedDateTime;

@Data
public class AuthorizeResponse {

    @SerializedName("APIKey")
    private String apiKey;

    private ZonedDateTime validUntil;

}
