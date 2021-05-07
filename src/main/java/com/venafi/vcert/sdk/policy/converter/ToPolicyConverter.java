package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

public interface ToPolicyConverter<T> {
    PolicySpecification convertToPolicy(T t) throws Exception;
}
