package com.venafi.vcert.sdk.connectors.cloud.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Team {

    private String id;
    private String name;
    private String role;
    private String companyId;
}
