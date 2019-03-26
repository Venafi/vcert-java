package com.venafi.vcert.sdk.connectors.cloud.domain;

import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class User {

    private String username;
    private String id;
    private String companyId;
    private String emailAddress;
    private String userType;
    private String userAccountType;
    private String userStatus;
    private OffsetDateTime creationDate;

}
