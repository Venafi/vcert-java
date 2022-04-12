package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class IdentityEntry {

    private String fullName;
    private String name;
    private String prefix;
    private String prefixedName;
    private String prefixedUniversal;
    private int type;
    private String universal;
}