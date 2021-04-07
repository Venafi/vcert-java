package com.venafi.vcert.sdk.policyspecification.parser;

import com.venafi.vcert.sdk.policyspecification.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policyspecification.parser.converter.IPolicySpecificationAPIConverter;
import com.venafi.vcert.sdk.policyspecification.parser.converter.TPPPolicySpecificationAPIConverter;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.IPolicySpecificationMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.PolicySpecificationJsonMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.PolicySpecificationYamlMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.validator.IPolicySpecificationValidator;
import com.venafi.vcert.sdk.policyspecification.parser.validator.TPPPolicySpecificationValidator;
import com.venafi.vcert.sdk.utils.VCertConstants;

import java.util.HashMap;
import java.util.Map;

public class TPPPolicySpecificationConverter extends PolicySpecificationConverter<TPPPolicy> {

    public static final TPPPolicySpecificationConverter TPPPolicySpecificationJsonConverter = new TPPPolicySpecificationConverter(VCertConstants.JSON_EXTENSION, PolicySpecificationJsonMarshal.INSTANCE);
    public static final TPPPolicySpecificationConverter TPPPolicySpecificationYamlConverter = new TPPPolicySpecificationConverter(VCertConstants.YAML_EXTENSION, PolicySpecificationYamlMarshal.INSTANCE);

    public static Map<String, TPPPolicySpecificationConverter> INSTANCES;

    private static void addInstance(String key, TPPPolicySpecificationConverter tppPolicySpecificationConverter){
        if(INSTANCES == null)
            INSTANCES = new HashMap<String, TPPPolicySpecificationConverter>();

        INSTANCES.put(key, tppPolicySpecificationConverter);
    }

    public static TPPPolicySpecificationConverter getInstance(String key){
        return INSTANCES.get(key);
    }

    private String key;
    private IPolicySpecificationMarshal policySpecificationMarshal;

    private TPPPolicySpecificationConverter(String key, IPolicySpecificationMarshal policySpecificationMarshal) {
        this.key = key;
        this.policySpecificationMarshal = policySpecificationMarshal;
        addInstance(key, this);
    }

    @Override
    protected IPolicySpecificationMarshal getPolicySpecificationMarshal() {
        return policySpecificationMarshal;
    }

    @Override
    protected IPolicySpecificationValidator getPolicySpecificationValidator() {
        return TPPPolicySpecificationValidator.INSTANCE;
    }

    @Override
    protected IPolicySpecificationAPIConverter<TPPPolicy> getPolicySpecificationAPIConverter() {
        return TPPPolicySpecificationAPIConverter.INSTANCE;
    }
}
