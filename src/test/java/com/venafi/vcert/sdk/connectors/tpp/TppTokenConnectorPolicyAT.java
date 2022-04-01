package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.IdentityEntry;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.IdentityInformation;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ValidateIdentityRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ValidateIdentityResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TppTokenConnectorPolicyAT {

    @RegisterExtension
    public final TppTokenConnectorResource connectorResource = new TppTokenConnectorResource();

    private String prefixedUniversal;
    private final String username = "osstestuser";

    @Test
    @DisplayName("TPP - Retrieve an Identity by username")
    public void browseIdentities() throws VCertException {
        try{
            IdentityEntry identity = connectorResource.connector().getTPPIdentity(username);
            Assertions.assertEquals(username, identity.name());
            prefixedUniversal = identity.prefixedUniversal();
        } catch (Exception e){
            System.out.println("");
        }
    }

    @Test
    @DisplayName("TPP - Retrieve the details of an Identity Entry by prefixedUniversal")
    public void validateIdentity() throws VCertException {
        if (prefixedUniversal == null){
            browseIdentities();
        }
        ValidateIdentityResponse response = connectorResource.connector().getTppAPI().validateIdentity(
                new ValidateIdentityRequest(
                        new IdentityInformation(prefixedUniversal)
                )
        );
        Assertions.assertNotNull(response);
        Assertions.assertEquals(username, response.id().name());
    }
}
