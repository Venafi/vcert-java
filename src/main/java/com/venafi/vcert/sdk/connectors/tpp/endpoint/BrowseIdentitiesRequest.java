package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class BrowseIdentitiesRequest {
    public static final int IDENTITY_USER = 1;
    public static final int IDENTITY_SECURITY_GROUP = 2;
    public static final int IDENTITY_DISTRIBUTION_GROUP = 8;
    public static final int ALL_IDENTITIES = IDENTITY_USER + IDENTITY_SECURITY_GROUP + IDENTITY_DISTRIBUTION_GROUP;

    @SerializedName("Filter")
    private final String filter;
    @SerializedName("Limit")
    private final int limit;
    @SerializedName("IdentityType")
    private final int type;
}