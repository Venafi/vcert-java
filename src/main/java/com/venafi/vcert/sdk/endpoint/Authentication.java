package com.venafi.vcert.sdk.endpoint;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Authentication {

    private String user;
    private String password; // todo: char[] ?
    private String apiKey;

    @Override
    public String toString() {
        return Authentication.class.getSimpleName() + "(user=" + user  + ", apiKey=" + apiKey + ", password=" + (!password.isEmpty() ? "****" : "not set") + ")";
    }
}
