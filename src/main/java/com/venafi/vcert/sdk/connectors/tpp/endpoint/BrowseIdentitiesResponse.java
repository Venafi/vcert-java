package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class BrowseIdentitiesResponse {

    @SerializedName("Identities")
    private IdentityEntry[] identities;
}