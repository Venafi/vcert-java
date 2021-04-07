package com.venafi.vcert.sdk.policyspecification.parser.converter;

import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

public interface IPolicySpecificationAPIConverter<T> {

    T convert(PolicySpecification policySpecification) throws Exception;

    PolicySpecification convert(T t) throws Exception;
}