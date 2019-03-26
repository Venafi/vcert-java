package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.endpoint.Authentication;
import lombok.Getter;


public class CloudConnector implements Connector {

    private Cloud cloud;

    @Getter
    private UserDetails user;

    CloudConnector(Cloud cloud) {
        this.cloud = cloud;
    }

    @Override
    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        this.user = cloud.authorize(auth.apiKey());
    }
}
