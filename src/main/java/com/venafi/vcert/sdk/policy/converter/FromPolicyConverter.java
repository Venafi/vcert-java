package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

public interface FromPolicyConverter<T> {

    T convertFromPolicy(PolicySpecification policySpecification) throws Exception;
}
