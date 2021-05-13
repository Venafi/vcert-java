package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policy.converter.cloud.CloudPolicyToPolicyConverter;
import com.venafi.vcert.sdk.policy.converter.cloud.PolicyToCloudPolicyConverter;
import com.venafi.vcert.sdk.policy.converter.cloud.CloudPolicySpecificationValidator;

public class CloudPolicySpecificationConverter extends PolicySpecificationConverter<CloudPolicy> {

    public static final CloudPolicySpecificationConverter INSTANCE = new CloudPolicySpecificationConverter();

    private CloudPolicySpecificationConverter(){}

    @Override
    protected IPolicySpecificationValidator getPolicySpecificationValidator() {
        return CloudPolicySpecificationValidator.INSTANCE;
    }

    @Override
    protected FromPolicyConverter<CloudPolicy> getFromPolicyConverter() {
        return PolicyToCloudPolicyConverter.INSTANCE;
    }

    @Override
    protected ToPolicyConverter<CloudPolicy> getToPolicyConverter() {
        return CloudPolicyToPolicyConverter.INSTANCE;
    }
}
