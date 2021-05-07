package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

public abstract class PolicySpecificationConverter<T> {

    public T convertFromPolicySpecification(PolicySpecification policySpecification) throws Exception{
        getPolicySpecificationValidator().validate(policySpecification);
        return getFromPolicyConverter().convertFromPolicy(policySpecification);
    }

    public PolicySpecification convertToPolicySpecification(T t) throws Exception{
        return getToPolicyConverter().convertToPolicy(t);
    }

    protected abstract IPolicySpecificationValidator getPolicySpecificationValidator();
    protected abstract FromPolicyConverter<T> getFromPolicyConverter();
    protected abstract ToPolicyConverter<T> getToPolicyConverter();
}
