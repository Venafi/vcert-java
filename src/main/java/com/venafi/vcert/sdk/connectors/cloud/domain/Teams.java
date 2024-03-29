package com.venafi.vcert.sdk.connectors.cloud.domain;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class Teams {

    @SerializedName("teams")
    private List<Team> teams;
}
