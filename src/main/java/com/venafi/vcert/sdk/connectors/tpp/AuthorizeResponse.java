package com.venafi.vcert.sdk.connectors.tpp;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@SuppressWarnings("WeakerAccess")
public class AuthorizeResponse {

    @SerializedName("APIKey")
    private String apiKey;

    private OffsetDateTime validUntil;

}
