package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.connectors.tpp.TppPolicyConstants;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class GetPolicyRequest {

    @SerializedName("PolicyDN")
    private final String policyDN;
}
