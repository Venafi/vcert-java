package com.venafi.vcert.sdk.policyspecification.parser.marshal;

import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

public interface IPolicySpecificationMarshal {

    PolicySpecification unmarshal(String string) throws VCertMarshalException;
    String marshal(PolicySpecification policySpecification) throws VCertMarshalException;
}