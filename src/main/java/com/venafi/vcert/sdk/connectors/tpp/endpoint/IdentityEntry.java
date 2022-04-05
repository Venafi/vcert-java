package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class IdentityEntry {

    @SerializedName("FullName")
    private String fullName;
    @SerializedName("Name")
    private String name;
    @SerializedName("Prefix")
    private String prefix;
    @SerializedName("PrefixedName")
    private String prefixedName;
    @SerializedName("PrefixedUniversal")
    private String prefixedUniversal;
    @SerializedName("Type")
    private int type;
    @SerializedName("Universal")
    private String universal;
}