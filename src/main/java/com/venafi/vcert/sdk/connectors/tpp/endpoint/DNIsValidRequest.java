package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DNIsValidRequest {

    @SerializedName("ObjectDN")
    private String objectDN;
}
