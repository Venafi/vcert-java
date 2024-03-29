package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.IdentityEntry;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.IdentityInformation;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ValidateIdentityRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ValidateIdentityResponse;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.utils.TppTestUtils;

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
        IdentityEntry identity = connectorResource.connector().getTPPIdentity(username);
        Assertions.assertEquals(username, identity.name());
        prefixedUniversal = identity.prefixedUniversal();
    }

//    @Test
//    @DisplayName("TPP - Retrieve and Identity using a partial match. Ensure that only one entry is returned")
//    public void browseIdentitiesPartialMatch() throws VCertException {
//        IdentityEntry identity = connectorResource.connector().getTPPIdentity(TestUtils.TPP_IDENTITY_USER);
//        Assertions.assertEquals(TestUtils.TPP_IDENTITY_USER, identity.name());
//    }

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

    @Test
    @DisplayName("TPP - Create a policy with contacts and retrieve it")
    public void createAndGetPolicyContacts() throws VCertException {
        TppTokenConnector connector = connectorResource.connector();

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();
        policySpecification.users(new String[]{"osstestuser"});
        String zone = TppTestUtils.getRandomZone();
        connector.setPolicy(zone, policySpecification);
        PolicySpecification psReturned = connector.getPolicy(zone);

        Assertions.assertEquals(1, psReturned.users().length);
        Assertions.assertEquals("osstestuser", psReturned.users()[0]);
    }
}