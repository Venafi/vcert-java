package com.venafi.vcert.sdk.policyspecification.parser.converter;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

public class CloudPolicySpecificationAPIConverter implements IPolicySpecificationAPIConverter<CertificateIssuingTemplate> {

    public static final CloudPolicySpecificationAPIConverter INSTANCE = new CloudPolicySpecificationAPIConverter();

    private CloudPolicySpecificationAPIConverter(){}

    @Override
    public CertificateIssuingTemplate convert(PolicySpecification policySpecification) throws Exception {
        return null;
    }

    @Override
    public PolicySpecification convert(CertificateIssuingTemplate certificateIssuingTemplate) throws Exception {
        return null;
    }
}
