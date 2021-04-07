package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class SubjectResponse {
    @SerializedName("Organization")
    private SingleValueAttribute<String> organization;
    @SerializedName("OrganizationalUnit")
    private MultiValueAttribute<String> organizationalUnit;
    @SerializedName("City")
    private SingleValueAttribute<String> city;
    @SerializedName("State")
    private SingleValueAttribute<String> state;
    @SerializedName("Country")
    private SingleValueAttribute<String> country;
}
