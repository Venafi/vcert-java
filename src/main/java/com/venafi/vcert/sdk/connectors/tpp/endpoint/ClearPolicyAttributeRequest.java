package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.connectors.tpp.TppPolicyConstants;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class ClearPolicyAttributeRequest {

    @SerializedName("ObjectDN")
    private final String objectDN;
    @SerializedName("Class")
    private final String objectClass = TppPolicyConstants.POLICY_ATTRIBUTE_CLASS;
    @SerializedName("AttributeName")
    private final String attributeName;
}
