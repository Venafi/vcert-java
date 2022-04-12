package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class ValidateIdentityResponse {

    @SerializedName("ID")
    private IdentityEntry id;
}
