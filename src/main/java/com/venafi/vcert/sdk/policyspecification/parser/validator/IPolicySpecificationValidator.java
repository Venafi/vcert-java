package com.venafi.vcert.sdk.policyspecification.parser.validator;

import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

public interface IPolicySpecificationValidator {
    void validate(PolicySpecification policySpecification) throws Exception;
}
