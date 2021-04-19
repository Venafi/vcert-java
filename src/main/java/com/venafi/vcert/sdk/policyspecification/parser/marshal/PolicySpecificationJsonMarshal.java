package com.venafi.vcert.sdk.policyspecification.parser.marshal;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

public class PolicySpecificationJsonMarshal implements IPolicySpecificationMarshal {

    public static final PolicySpecificationJsonMarshal INSTANCE = new PolicySpecificationJsonMarshal();

    private PolicySpecificationJsonMarshal(){}

    @Override
    public PolicySpecification unmarshal(String jsonString) throws VCertMarshalException {
        try {
            return new Gson().fromJson(jsonString, PolicySpecification.class);
        }catch (Exception e){
            throw new VCertMarshalException(e);
        }
    }

    @Override
    public String marshal(PolicySpecification policySpecification) throws VCertMarshalException {
        try {
            return new GsonBuilder().setPrettyPrinting().create().toJson(policySpecification);
        }catch (Exception e){
            throw new VCertMarshalException(e);
        }
    }
}
