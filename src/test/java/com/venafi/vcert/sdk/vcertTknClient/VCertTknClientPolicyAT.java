package com.venafi.vcert.sdk.vcertTknClient;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.utils.TppTestUtils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class VCertTknClientPolicyAT {

    @RegisterExtension
    public final VCertTknClientResource connectorResource = new VCertTknClientResource();

    @Test
    @DisplayName("VCertTknClient - Create a policy with contacts and retrieve it")
    public void createAndGetPolicyContacts() throws VCertException {
        VCertTknClient client = connectorResource.client();

        PolicySpecification policySpecification = TppTestUtils.getPolicySpecification();
        policySpecification.users(new String[]{"osstestuser"});
        String zone = TppTestUtils.getRandomZone();
        client.setPolicy(zone, policySpecification);
        PolicySpecification psReturned = client.getPolicy(zone);

        Assertions.assertEquals(1, psReturned.users().length);
        Assertions.assertEquals("osstestuser", psReturned.users()[0]);
    }
}