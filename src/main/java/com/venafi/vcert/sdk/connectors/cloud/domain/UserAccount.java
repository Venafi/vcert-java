package com.venafi.vcert.sdk.connectors.cloud.domain;

import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
public class UserAccount {
    private String username;
    private String password;
    private String firstname;
    private String lastname;
    private String companyId;
    private String companyName;
    private String userAccountType;
    private String greCaptchaResponse;

    public UserAccount(String username, String userAccountType) {
        this.username = username;
        this.userAccountType = userAccountType;
    }
}
