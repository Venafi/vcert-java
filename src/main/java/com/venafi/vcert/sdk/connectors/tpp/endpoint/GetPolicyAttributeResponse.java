package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class GetPolicyAttributeResponse {
    @SerializedName("Error")
    private String error;
    @SerializedName("Locked")
    private final boolean locked;
    @SerializedName("Result")
    private int result;
    @SerializedName("Values")
    private final Object[] values;
}

