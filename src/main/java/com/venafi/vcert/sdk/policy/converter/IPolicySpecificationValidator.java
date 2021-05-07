package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

public interface IPolicySpecificationValidator {
    void validate(PolicySpecification policySpecification) throws Exception;
}
