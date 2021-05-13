package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class CreateDNResponse {
    @SerializedName("Error")
    private String error;
    @SerializedName("Result")
    private int result;
    @SerializedName("Object")
    private ObjectDN objectDN;
}

