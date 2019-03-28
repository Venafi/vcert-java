package com.venafi.vcert.sdk.connectors.cloud.domain;

import lombok.Data;

@Data
public class UserDetails {

    private User user;
    private Company company;
    private ApiKey apiKey;

}
