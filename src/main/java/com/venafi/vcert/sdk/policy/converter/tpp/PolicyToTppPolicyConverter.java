package com.venafi.vcert.sdk.policy.converter.tpp;

import com.venafi.vcert.sdk.policy.api.domain.AttributeLockable;
import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policy.domain.*;
import com.venafi.vcert.sdk.policy.converter.FromPolicyConverter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;

public class PolicyToTppPolicyConverter implements FromPolicyConverter<TPPPolicy> {

    public static PolicyToTppPolicyConverter INSTANCE = new PolicyToTppPolicyConverter();

    private PolicyToTppPolicyConverter(){}

    public TPPPolicy convertFromPolicy(PolicySpecification policySpecification ) throws Exception {
        TPPPolicy tppPolicy = new TPPPolicy();

        //copying the policy name
        copyStringProperty(policySpecification, tppPolicy, PolicySpecification::name, TPPPolicy::policyName);
        //copying the contact
        copyArrayStringProperty(policySpecification, tppPolicy, PolicySpecification::users, TPPPolicy::contact);
        //copying the approver
        copyArrayStringProperty(policySpecification, tppPolicy, PolicySpecification::approvers, TPPPolicy::approver);

        //setting policy's attributes
        copyArrayStringProperty(policySpecification.policy(), tppPolicy, Policy::domains, TPPPolicy::domainSuffixWhiteList);
        copyProhibitWildcard(tppPolicy, policySpecification);
        copyStringProperty(policySpecification.policy(), tppPolicy, Policy::certificateAuthority, TPPPolicy::certificateAuthority);

        //copying management type
        setManagementType(tppPolicy, policySpecification);

        //setting policy subject attributes
        copySubjectAttributes( policySpecification, tppPolicy);

        //setting policy keypair
        copyKeyPairAttributes(policySpecification, tppPolicy);

        //setting policy alt names
        setProhibitedSANTypes(tppPolicy, policySpecification);

        return tppPolicy;
    }

    private <S, T> void copyStringProperty(S source, T target, Function<S, String> getter, BiConsumer<T, String> setter){
        if( source != null) {
            String stringValue = getter.apply(source);
            if (stringValue != null && !stringValue.equals(""))
                setter.accept(target, stringValue);
        }
    }

    private <S, T, V> void copyArrayStringProperty(S source, T target, Function<S, V[]> getter, BiConsumer<T, V[]> setter){
        if( source != null) {
            V[] arrayValue = getter.apply(source);
            if (arrayValue != null && arrayValue.length > 0)
                setter.accept(target, arrayValue);
        }
    }

    private <S, D, T> void copyAttributeLockableString( S source, D defaultSource, T target, Function<S, String> sourceGetter, Function<D, String> defaultGetter, BiConsumer<T, AttributeLockable> setter){
        if(source != null ) {
            String value = sourceGetter.apply(source);
            if(value != null && !value.equals(""))
                setter.accept(target, new AttributeLockable(new String[]{value}, true));
        } else
        if( defaultSource != null ) {
            String value = defaultGetter.apply(defaultSource);
            if(value != null && !value.equals(""))
                setter.accept(target, new AttributeLockable(new String[]{value}, false));
        }
    }

    private <S, D, T> void copyAttributeLockableStringMultiValue(S source, D defaultSource, T target, Function<S, String[]> sourceGetter, Function<D, String> defaultGetter, BiConsumer<T, AttributeLockable> setter){

        if(source != null && sourceGetter.apply(source) != null) {
            String[] arrayValues = filterEmptyStrings(sourceGetter.apply(source));
            if( arrayValues != null &&arrayValues.length == 1)
                setter.accept(target, new AttributeLockable(new String[]{arrayValues[0]}, true));
        } else
            if( defaultSource != null ) {
                String value = defaultGetter.apply(defaultSource);
                if(value != null && !value.equals(""))
                    setter.accept(target, new AttributeLockable(new String[]{value}, false));
            }
    }

    private void setManagementType( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null && policy.autoInstalled() != null )
            tppPolicy.managementType( ManagementTypes.from( policy.autoInstalled() ).value, true);
    }

    private void copyProhibitWildcard(TPPPolicy tppPolicy, PolicySpecification policySpecification ) {
        Policy policy = policySpecification.policy();
        if(policy != null && policy.wildcardAllowed() != null )
            tppPolicy.prohibitWildcard( !policy.wildcardAllowed() ? 1 : 0);
    }

    private void copySubjectAttributes( PolicySpecification policySpecification, TPPPolicy tppPolicy){
        Subject policySubject = policySpecification.policy() != null && policySpecification.policy().subject() != null ? policySpecification.policy().subject() : null;
        DefaultsSubject defaultsSubject = policySpecification.defaults() != null && policySpecification.defaults().subject() != null ? policySpecification.defaults().subject() : null;

        //copying Org values
        copyAttributeLockableStringMultiValue(policySubject, defaultsSubject, tppPolicy, Subject::orgs, DefaultsSubject::org, TPPPolicy::organization);

        //copying OrgUnits
        copyOrganizationalUnit(tppPolicy, policySpecification);

        //copying City
        copyAttributeLockableStringMultiValue(policySubject, defaultsSubject, tppPolicy, Subject::localities, DefaultsSubject::locality, TPPPolicy::city);

        //Copying state
        copyAttributeLockableStringMultiValue(policySubject, defaultsSubject, tppPolicy, Subject::states, DefaultsSubject::state, TPPPolicy::state);

        //Copying country
        copyAttributeLockableStringMultiValue(policySubject, defaultsSubject, tppPolicy, Subject::countries, DefaultsSubject::country, TPPPolicy::country);
    }

    private void copyOrganizationalUnit(TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        String[] subjectOrgUnits = policySpecification.policy() != null && policySpecification.policy().subject() != null && policySpecification.policy().subject().orgUnits() != null
                ? filterEmptyStrings( policySpecification.policy().subject().orgUnits()) : null;
        String[] defaultsOrgUnits = policySpecification.defaults() != null && policySpecification.defaults().subject() != null && policySpecification.defaults().subject().orgUnits() != null
                ? filterEmptyStrings( policySpecification.defaults().subject().orgUnits()) : null;

        if (subjectOrgUnits!= null && subjectOrgUnits.length>0)
            tppPolicy.organizationalUnit(subjectOrgUnits, true);
        else
        if (defaultsOrgUnits!=null && defaultsOrgUnits.length>0)
            tppPolicy.organizationalUnit( defaultsOrgUnits, false);
    }

    private void copyKeyPairAttributes( PolicySpecification policySpecification, TPPPolicy tppPolicy){

        KeyPair policyKeyPair = policySpecification.policy() != null && policySpecification.policy().keyPair() != null ? policySpecification.policy().keyPair() : null;
        DefaultsKeyPair defaultsKeyPair = policySpecification.defaults() != null && policySpecification.defaults().keyPair() != null ? policySpecification.defaults().keyPair() : null;

        //copying the keyAlgorithm
        copyAttributeLockableStringMultiValue(policyKeyPair, defaultsKeyPair, tppPolicy, KeyPair::keyTypes, DefaultsKeyPair::keyType, TPPPolicy::keyAlgorithm);

        //copying the keyBitStrength
        setKeyBitStrength(tppPolicy, policySpecification);

        //copying the ellipticcurves
        copyAttributeLockableStringMultiValue(policyKeyPair, defaultsKeyPair, tppPolicy, KeyPair::ellipticCurves, DefaultsKeyPair::ellipticCurve, TPPPolicy::ellipticCurve);

        //copying the manualCSR
        setManualCsr(tppPolicy, policySpecification);

        //copying the AllowPrivateKeyReuse
        setAllowPrivateKeyReuse(tppPolicy, policySpecification);

        //copying the wantRenewal
        setWantRenewal(tppPolicy, policySpecification);

        //copying the ProhibitedSANTypes
        setProhibitedSANTypes(tppPolicy, policySpecification);
    }

    private void setKeyBitStrength( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null && policy.keyPair() != null ) {
            Integer[] rsaKeySizes = policy.keyPair().rsaKeySizes();
            if( rsaKeySizes != null && rsaKeySizes.length == 1 )
                tppPolicy.keyBitStrength( rsaKeySizes[0].toString(), true);
        } else
        if(defaults != null && defaults.keyPair() != null && defaults.keyPair().rsaKeySize() != null )
            tppPolicy.keyBitStrength( defaults.keyPair().rsaKeySize().toString(), false);

    }

    private void setManualCsr( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null && policy.keyPair() != null && policy.keyPair().serviceGenerated() != null )
            tppPolicy.manualCsr( policy.keyPair().serviceGenerated() ? "0" : "1", true);
        else
        if(defaults != null && defaults.keyPair() != null && defaults.keyPair().serviceGenerated() != null )
            tppPolicy.manualCsr(defaults.keyPair().serviceGenerated() ? "0" : "1", false);
    }

    private void setAllowPrivateKeyReuse( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();

        if(policy != null && policy.keyPair() != null && policy.keyPair().reuseAllowed() != null )
            tppPolicy.allowPrivateKeyReuse( policy.keyPair().reuseAllowed() ? "1" : "0", true);
    }

    private void setWantRenewal( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();

        if(policy != null && policy.keyPair() != null && policy.keyPair().reuseAllowed() != null )
            tppPolicy.wantRenewal( policy.keyPair().reuseAllowed() ? "1" : "0", true);
    }

    private void setProhibitedSANTypes( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();

        if( policy != null ) {
            SubjectAltNames subjectAltNames = policy.subjectAltNames();

            if ( subjectAltNames != null ){
                List<String> prohibitedSANTypes = new ArrayList<>();

                if ( subjectAltNames.dnsAllowed() != null && !subjectAltNames.dnsAllowed() )
                    prohibitedSANTypes.add(AltName.DNS.value);

                if ( subjectAltNames.ipAllowed() != null && !subjectAltNames.ipAllowed() )
                    prohibitedSANTypes.add(AltName.IP.value);

                if ( subjectAltNames.emailAllowed() != null && !subjectAltNames.emailAllowed() )
                    prohibitedSANTypes.add(AltName.EMAIL.value);

                if ( subjectAltNames.uriAllowed() != null && !subjectAltNames.uriAllowed() )
                    prohibitedSANTypes.add(AltName.URI.value);

                if ( subjectAltNames.upnAllowed() != null && !subjectAltNames.upnAllowed() )
                    prohibitedSANTypes.add(AltName.UPN.value);

                if( prohibitedSANTypes.size()>0 )
                    tppPolicy.prohibitedSANTypes(prohibitedSANTypes.toArray(new String[0]));
            }
        }
    }

    private String[] filterEmptyStrings( String[] strArray){
        Predicate<String> empty = String::isEmpty;
        Predicate<String> notEmpty = empty.negate();

        Function<String[], String[]> filter = arr -> Arrays.asList(arr).stream().filter(notEmpty).toArray(size -> new String[size]);

        return filter.apply( strArray );
    }
}
