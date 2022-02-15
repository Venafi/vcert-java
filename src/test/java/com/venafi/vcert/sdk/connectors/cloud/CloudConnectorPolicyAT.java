/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import static org.junit.Assert.assertEquals;

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
	
	    assertEquals(policySpecification, policySpecificationReturned);
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
	
	    assertEquals(policySpecification, policySpecificationReturned);
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

}
