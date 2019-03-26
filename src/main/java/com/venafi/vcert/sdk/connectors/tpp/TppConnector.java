package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.endpoint.Authentication;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;


public class TppConnector implements Connector {

    private final Tpp tpp;
    @Getter
    private String apiKey;

    TppConnector(Tpp tpp) {
        this.tpp = tpp;
    }

    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        AuthorizeResponse response = tpp.authorize(new AuthorizeRequest(auth.user(), auth.password()));
        apiKey = response.apiKey();
    }

    @Data
    @AllArgsConstructor
    static class AuthorizeRequest {
        private String username;
        private String password;
    }
}
