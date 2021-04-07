package com.venafi.vcert.sdk.policyspecification.parser;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.policyspecification.parser.converter.CloudPolicySpecificationAPIConverter;
import com.venafi.vcert.sdk.policyspecification.parser.converter.IPolicySpecificationAPIConverter;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.IPolicySpecificationMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.PolicySpecificationJsonMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.PolicySpecificationYamlMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.validator.CloudPolicySpecificationValidator;
import com.venafi.vcert.sdk.policyspecification.parser.validator.IPolicySpecificationValidator;
import com.venafi.vcert.sdk.utils.VCertConstants;

import java.util.HashMap;
import java.util.Map;

public class CloudPolicySpecificationConverter extends PolicySpecificationConverter<CertificateIssuingTemplate> {

    public static final CloudPolicySpecificationConverter CloudPolicySpecificationJsonConverter = new CloudPolicySpecificationConverter(VCertConstants.JSON_EXTENSION, PolicySpecificationJsonMarshal.INSTANCE);
    public static final CloudPolicySpecificationConverter CloudPolicySpecificationYamlConverter = new CloudPolicySpecificationConverter(VCertConstants.YAML_EXTENSION, PolicySpecificationYamlMarshal.INSTANCE);

    public static final Map<String, CloudPolicySpecificationConverter> INSTANCES = new HashMap<String, CloudPolicySpecificationConverter>();

    public static CloudPolicySpecificationConverter getInstance(String key){
        return INSTANCES.get(key);
    }

    private String key;
    private IPolicySpecificationMarshal policySpecificationMarshal;

    public CloudPolicySpecificationConverter(String key, IPolicySpecificationMarshal policySpecificationMarshal) {
        this.key = key;
        this.policySpecificationMarshal = policySpecificationMarshal;
        INSTANCES.put(key, this);
    }

    @Override
    protected IPolicySpecificationMarshal getPolicySpecificationMarshal() {
        return policySpecificationMarshal;
    }

    @Override
    protected IPolicySpecificationValidator getPolicySpecificationValidator() {
        return CloudPolicySpecificationValidator.INSTANCE;
    }

    @Override
    protected IPolicySpecificationAPIConverter<CertificateIssuingTemplate> getPolicySpecificationAPIConverter() {
        return CloudPolicySpecificationAPIConverter.INSTANCE;
    }
}
