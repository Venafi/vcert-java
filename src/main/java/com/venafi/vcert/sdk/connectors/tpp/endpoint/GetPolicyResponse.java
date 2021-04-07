package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class GetPolicyResponse {
    @SerializedName("Error")
    private String error;
    @SerializedName("Policy")
    private PolicyResponse policy;

}