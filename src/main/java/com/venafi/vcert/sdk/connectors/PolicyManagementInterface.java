package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

public interface PolicyManagementInterface {

  /**
   * Reads the policy configuration for a specific zone in Venafi
   *
   * @param zone
   * @return
   * @throws VCertException
   */
  Policy readPolicyConfiguration(String zone) throws VCertException;

  /**
   * Create/update a policy based on the policySpecification passed as argument.
   *
   * @param policyName
   * @param policySpecification
   * @throws VCertException
   */
  void setPolicy(String policyName, PolicySpecification policySpecification) throws VCertException;

  /**
   * Returns the policySpecification from the policy which matches with the policyName argument.
   *
   * @param policyName
   * @return
   * @throws VCertException
   */
  PolicySpecification getPolicy(String policyName) throws VCertException;
}
