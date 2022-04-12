package com.venafi.vcert.sdk.connectors.cloud;

import static org.junit.Assert.assertEquals;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.connectors.cloud.domain.User;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.utils.VCertConstants;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class CloudConnectorPolicyAT {
	
	@RegisterExtension
	public final CloudConnectorResource connectorResource = new CloudConnectorResource();

	@Test
	@DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods")
	public void createAndGetPolicy() throws VCertException {
		
		CloudConnector connector = connectorResource.connector();
	
	    String policyName = CloudTestUtils.getRandomZone();
	
	    PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
	
	    connector.setPolicy(policyName, policySpecification);
	
	    PolicySpecification policySpecificationReturned = connector.getPolicy(policyName);
	
	    //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
	    //due it doesn't contain it
	    policySpecification.name(policySpecificationReturned.name());
	    //The returned policySpecification will contains the default cloud CA, then it will needed
	    //to set it to the policySpecification source
	    policySpecification.policy().certificateAuthority(VCertConstants.CLOUD_DEFAULT_CA);
	
	    Assertions.assertEquals(policySpecification, policySpecificationReturned);
	}

	@Test
	@DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods for Digicert CA")
	public void createAndGetPolicyForDigicert() throws VCertException {
		
		CloudConnector connector = connectorResource.connector();
	
	    String policyName = CloudTestUtils.getRandomZone();
	
	    PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
	    policySpecification.policy().certificateAuthority(TestUtils.CLOUD_DIGICERT_CA_NAME);
	
	    connector.setPolicy(policyName, policySpecification);
	
	    PolicySpecification policySpecificationReturned = connector.getPolicy(policyName);
	    
	    //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
	    //due it doesn't contain it
	    policySpecification.name(policySpecificationReturned.name());
	
	    Assertions.assertEquals(policySpecification, policySpecificationReturned);
	}

	@Test
	@DisplayName("Cloud - Testing the setPolicy() and getPolicy() methods for Entrust CA")
	public void createAndGetPolicyForEntrust() throws VCertException {
		
		CloudConnector connector = connectorResource.connector();
	
	    String policyName = CloudTestUtils.getRandomZone();
	
	    PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
	    policySpecification.policy().certificateAuthority(TestUtils.CLOUD_ENTRUST_CA_NAME);
	
	    connector.setPolicy(policyName, policySpecification);
	
	    PolicySpecification policySpecificationReturned = connector.getPolicy(policyName);
	
	    //The returned policySpecification will have the policy's name so it will copied to the source policySpecification
	    //due it doesn't contain it
	    policySpecification.name(policySpecificationReturned.name());
	
	    assertEquals(policySpecification, policySpecificationReturned);
	}

	@Test
	@DisplayName("Cloud - Testing the userByName endpoint")
	public void getUserByName() throws VCertException{
		Config config = null;
		Cloud cloud = Cloud.connect(config);

		String username = "pki-admin@opensource.qa.venafi.io";
		String apiKey = TestUtils.API_KEY;
		UserResponse response = cloud.retrieveUser(username, apiKey);
		Assertions.assertNotNull(response);
		Assertions.assertEquals(1, response.users().size());
		User user = response.users().get(0);
		Assertions.assertEquals(username, user.username());
	}

	@Test
	@DisplayName("Cloud - Testing get and set users from Policy Specification into Application")
	public void createAndGetPolicyContacts() throws VCertException {
		CloudConnector connector = connectorResource.connector();
		String policyName = CloudTestUtils.getRandomZone();
		PolicySpecification policySpecification = CloudTestUtils.getPolicySpecification();
		policySpecification.users(new String[]{"pki-admin@opensource.qa.venafi.io","resource-owner@opensource.qa.venafi.io"});
		connector.setPolicy(policyName, policySpecification);
		PolicySpecification psReturned = connector.getPolicy(policyName);

		Assertions.assertEquals(2, psReturned.users().length);
		Assertions.assertEquals("pki-admin@opensource.qa.venafi.io", psReturned.users()[0]);
		Assertions.assertEquals("resource-owner@opensource.qa.venafi.io", psReturned.users()[1]);
	}
}
