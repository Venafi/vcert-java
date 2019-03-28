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

    // present in JSON but not in Go SDK
//    @SerializedName("firstname")
//    private String firstName;
//    @SerializedName("lastname")
//    private String lastName;
//    private Collection<String> roles;
//    private OffsetDateTime firstLoginDate;

}
