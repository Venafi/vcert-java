package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class ObjectDN {
    @SerializedName("AbsoluteGUID")
    private String absoluteGUID;
    @SerializedName("DN")
    private String dn;
    @SerializedName("GUID")
    private String guid;
    @SerializedName("Id")
    private String id;
    @SerializedName("Name")
    private String name;
    @SerializedName("Parent")
    private String parent;
    @SerializedName("Revision")
    private String revision;
    @SerializedName("TypeName")
    private String typeName;
}
