package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policy.converter.tpp.*;
import com.venafi.vcert.sdk.policy.converter.tpp.TPPPolicySpecificationValidator;

public class TPPPolicySpecificationConverter extends PolicySpecificationConverter<TPPPolicy> {

    public static final TPPPolicySpecificationConverter INSTANCE = new TPPPolicySpecificationConverter();

    private TPPPolicySpecificationConverter(){}

    @Override
    protected IPolicySpecificationValidator getPolicySpecificationValidator() {
        return TPPPolicySpecificationValidator.INSTANCE;
    }

    @Override
    protected FromPolicyConverter<TPPPolicy> getFromPolicyConverter() {
        return PolicyToTppPolicyConverter.INSTANCE;
    }

    @Override
    protected ToPolicyConverter<TPPPolicy> getToPolicyConverter() {
        return TppPolicyToPolicyConverter.INSTANCE;
    }
}
