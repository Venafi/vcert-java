package com.venafi.vcert.sdk.policy.converter;

import com.venafi.vcert.sdk.policy.api.domain.AttributeLockable;
import com.venafi.vcert.sdk.policy.domain.*;

import java.util.function.BiConsumer;
import java.util.function.Function;

public abstract class ToPolicyConverterAbstract<T> implements ToPolicyConverter<T> {

    public abstract PolicySpecification convertToPolicy(T t) throws Exception;

    public enum TypePSAToCreate {
        NORMAL, DEFAULT, NONE;
    }

    protected <S> TypePSAToCreate shouldCreateAttribute(S source, Function<S, AttributeLockable> sourceGetter){
        AttributeLockable<String> attributeLockable = sourceGetter.apply(source);

        if (attributeLockable != null && attributeLockable.values().length > 0 ) {
            if (attributeLockable.lock() )
                return TypePSAToCreate.NORMAL;
            else
                return TypePSAToCreate.DEFAULT;
        }

        return TypePSAToCreate.NONE;
    }

    protected <N, P> N getNestedObject(P parent, Function<P, N> getter, BiConsumer<P, N> setter, Class<N> clazz) throws Exception{
        N nested = getter.apply(parent);

        if ( nested == null) {
            nested = clazz.newInstance();
            setter.accept(parent , nested);
        }

        return nested;
    }

    protected Policy getPolicyFromPolicySpecification(PolicySpecification policySpecification ) throws Exception {
        return getNestedObject(policySpecification, PolicySpecification::policy, PolicySpecification::policy, Policy.class);
    }

    protected Subject getSubjectFromPolicy(Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::subject, Policy::subject, Subject.class);
    }

    protected Subject getSubjectFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    protected KeyPair getKeyPairFromPolicy(Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::keyPair, Policy::keyPair, KeyPair.class);
    }

    protected KeyPair getKeyPairFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getKeyPairFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    protected SubjectAltNames getSubjectAltNamesFromPolicy(Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::subjectAltNames, Policy::subjectAltNames, SubjectAltNames.class);
    }

    protected SubjectAltNames getSubjectAltNamesFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectAltNamesFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    protected Defaults getDefaultsFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getNestedObject(policySpecification, PolicySpecification::defaults, PolicySpecification::defaults, Defaults.class);
    }

    protected DefaultsSubject getSubjectFromDefaults( Defaults defaults ) throws Exception {
        return getNestedObject(defaults, Defaults::subject, Defaults::subject, DefaultsSubject.class);
    }

    protected DefaultsSubject getDefaultsSubjectFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectFromDefaults(getDefaultsFromPolicySpecification(policySpecification));
    }

    protected DefaultsKeyPair getKeyPairFromDefaults( Defaults defaults ) throws Exception {
        return getNestedObject(defaults, Defaults::keyPair, Defaults::keyPair, DefaultsKeyPair.class);
    }

    protected DefaultsKeyPair getDefaultsKeyPairFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getKeyPairFromDefaults(getDefaultsFromPolicySpecification(policySpecification));
    }

}
