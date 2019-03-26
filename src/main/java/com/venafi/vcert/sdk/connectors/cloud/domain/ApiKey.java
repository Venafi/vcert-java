package com.venafi.vcert.sdk.connectors.cloud.domain;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.Collection;

@Data
public class ApiKey {

    private String username;
    private String apiVersion;
    private String apiKeyStatus;
    private OffsetDateTime creationDate;
    private OffsetDateTime validityStartDate;
    private OffsetDateTime validityEndDate;

    @SerializedName("apitypes")
    private Collection<String> apiTypes;

}
