package com.venafi.vcert.sdk.policyspecification.parser.converter;

import com.venafi.vcert.sdk.policyspecification.api.domain.AttributeLockable;
import com.venafi.vcert.sdk.policyspecification.domain.*;
import com.venafi.vcert.sdk.policyspecification.api.domain.TPPPolicy;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class TPPPolicySpecificationAPIConverter implements IPolicySpecificationAPIConverter<TPPPolicy> {

    public static final TPPPolicySpecificationAPIConverter INSTANCE = new TPPPolicySpecificationAPIConverter();

    private TPPPolicySpecificationAPIConverter(){}

    @Override
    public TPPPolicy convert(PolicySpecification policySpecification) throws Exception {
        /*
		"owners": string[],					(permissions only)	prefixed name/universal
		"userAccess": string,					(permissions)	prefixed name/universal
		}
	*/
        return PolicySpecificationToTppPolicyConverter.convert(policySpecification);
    }

    @Override
    public PolicySpecification convert(TPPPolicy tppPolicy) throws Exception {
        return TPPPolicyToPolicySpecificationConverter.convert(tppPolicy);
    }
}

class PolicySpecificationToTppPolicyConverter {


    public static TPPPolicy convert( PolicySpecification policySpecification ) throws Exception {
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

        //setting policy subject attributes
        copySubjectAttributes( policySpecification, tppPolicy);

        //setting policy keypair
        copyKeyPairAttributes(policySpecification, tppPolicy);

        //setting policy alt names
        setProhibitedSANTypes(tppPolicy, policySpecification);

        return tppPolicy;
    }

    private static <S, T> void copyStringProperty(S source, T target, Function<S, String> getter, BiConsumer<T, String> setter){
        if( source != null) {
            String stringValue = getter.apply(source);
            if (stringValue != null && !stringValue.equals(""))
                setter.accept(target, stringValue);
        }
    }

    private static <S, T, V> void copyArrayStringProperty(S source, T target, Function<S, V[]> getter, BiConsumer<T, V[]> setter){
        if( source != null) {
            V[] arrayValue = getter.apply(source);
            if (arrayValue != null && arrayValue.length > 0)
                setter.accept(target, arrayValue);
        }
    }

    private static <S, D, T> void copyAttributeLockableString( S source, D defaultSource, T target, Function<S, String[]> sourceGetter, Function<D, String> defaultGetter, BiConsumer<T, AttributeLockable> setter){
        if(source != null ) {
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

    private static void copyProhibitWildcard(TPPPolicy tppPolicy, PolicySpecification policySpecification ) {
        Policy policy = policySpecification.policy();
        if(policy != null && policy.wildcardAllowed() != null )
            tppPolicy.prohibitWildcard( !policy.wildcardAllowed() ? 1 : 0);
    }

    private static void copySubjectAttributes( PolicySpecification policySpecification, TPPPolicy tppPolicy){
        Subject policySubject = policySpecification.policy() != null && policySpecification.policy().subject() != null ? policySpecification.policy().subject() : null;
        DefaultsSubject defaultsSubject = policySpecification.defaults() != null && policySpecification.defaults().subject() != null ? policySpecification.defaults().subject() : null;

        //copying Org values
        copyAttributeLockableString(policySubject, defaultsSubject, tppPolicy, Subject::orgs, DefaultsSubject::org, TPPPolicy::organization);

        //copying OrgUnits
        copyOrganizationalUnit(tppPolicy, policySpecification);

        //copying City
        copyAttributeLockableString(policySubject, defaultsSubject, tppPolicy, Subject::localities, DefaultsSubject::locality, TPPPolicy::city);

        //Copying state
        copyAttributeLockableString(policySubject, defaultsSubject, tppPolicy, Subject::states, DefaultsSubject::state, TPPPolicy::state);

        //Copying country
        copyAttributeLockableString(policySubject, defaultsSubject, tppPolicy, Subject::countries, DefaultsSubject::country, TPPPolicy::country);
    }

    private static void copyOrganizationalUnit(TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        String[] subjectOrgUnits = policySpecification.policy() != null && policySpecification.policy().subject() != null && policySpecification.policy().subject().orgUnits() != null
                ? filterEmptyStrings( policySpecification.policy().subject().orgUnits()) : null;
        String[] defaultsOrgUnits = policySpecification.defaults() != null && policySpecification.defaults().subject() != null && policySpecification.defaults().subject().orgUnits() != null
                ? filterEmptyStrings( policySpecification.defaults().subject().orgUnits()) : null;

        if (subjectOrgUnits.length>0)
            tppPolicy.organizationalUnit(subjectOrgUnits, true);
        else
            if (defaultsOrgUnits.length>0)
                tppPolicy.organizationalUnit( defaultsOrgUnits, false);
    }

    private static void copyKeyPairAttributes( PolicySpecification policySpecification, TPPPolicy tppPolicy){

        KeyPair policyKeyPair = policySpecification.policy() != null && policySpecification.policy().keyPair() != null ? policySpecification.policy().keyPair() : null;
        DefaultsKeyPair defaultsKeyPair = policySpecification.defaults() != null && policySpecification.defaults().keyPair() != null ? policySpecification.defaults().keyPair() : null;

        //copying the keyAlgorithm
        copyAttributeLockableString(policyKeyPair, defaultsKeyPair, tppPolicy, KeyPair::keyTypes, DefaultsKeyPair::keyType, TPPPolicy::keyAlgorithm);

        //copying the keyBitStrength
        setKeyBitStrength(tppPolicy, policySpecification);

        //copying the ellipticcurves
        copyAttributeLockableString(policyKeyPair, defaultsKeyPair, tppPolicy, KeyPair::ellipticCurves, DefaultsKeyPair::ellipticCurve, TPPPolicy::ellipticCurve);

        //copying the manualCSR
        setManualCsr(tppPolicy, policySpecification);

        //copying the AllowPrivateKeyReuse
        setAllowPrivateKeyReuse(tppPolicy, policySpecification);

        //copying the wantRenewal
        setWantRenewal(tppPolicy, policySpecification);

        //copying the ProhibitedSANTypes
        setProhibitedSANTypes(tppPolicy, policySpecification);
    }

    private static void setKeyBitStrength( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

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

    private static void setManualCsr( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null && policy.keyPair() != null && policy.keyPair().serviceGenerated() != null )
            tppPolicy.manualCsr( policy.keyPair().serviceGenerated() ? "0" : "1", true);
        else
            if(defaults != null && defaults.keyPair() != null && defaults.keyPair().serviceGenerated() != null )
                tppPolicy.manualCsr(defaults.keyPair().serviceGenerated() ? "0" : "1", false);
    }

    private static void setAllowPrivateKeyReuse( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();

        if(policy != null && policy.keyPair() != null && policy.keyPair().reuseAllowed() != null )
            tppPolicy.allowPrivateKeyReuse( policy.keyPair().reuseAllowed() ? "1" : "0", true);
    }

    private static void setWantRenewal( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

        Policy policy = policySpecification.policy();

        if(policy != null && policy.keyPair() != null && policy.keyPair().reuseAllowed() != null )
            tppPolicy.wantRenewal( policy.keyPair().reuseAllowed() ? "1" : "0", true);
    }

    private static void setProhibitedSANTypes( TPPPolicy tppPolicy, PolicySpecification policySpecification ) {

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

    private static String[] filterEmptyStrings( String[] strArray){
        Predicate<String> empty = String::isEmpty;
        Predicate<String> notEmpty = empty.negate();

        Function<String[], String[]> filter = arr -> Arrays.asList(arr).stream().filter(notEmpty).toArray(size -> new String[size]);

        return filter.apply( strArray );
    }
}

class TPPPolicyToPolicySpecificationConverter {

    public static PolicySpecification convert( TPPPolicy tppPolicy ) throws Exception {
        PolicySpecification policySpecification = new PolicySpecification();

        policySpecification.name( tppPolicy.policyName() );

        policySpecification.users( tppPolicy.contact() != null  && tppPolicy.contact().length > 0 ? tppPolicy.contact() : null );

        policySpecification.approvers( tppPolicy.approver() != null  && tppPolicy.approver().length > 0 ? tppPolicy.approver() : null);

        if( tppPolicy.domainSuffixWhiteList() != null && tppPolicy.domainSuffixWhiteList().length >0 )
            getPolicyFromPolicySpecification( policySpecification ).domains( tppPolicy.domainSuffixWhiteList());

        if( tppPolicy.prohibitWildcard() != null )
            getPolicyFromPolicySpecification( policySpecification ).wildcardAllowed( !(tppPolicy.prohibitWildcard() == 1) );

        if( tppPolicy.certificateAuthority() != null && !tppPolicy.certificateAuthority().equals(""))
            getPolicyFromPolicySpecification( policySpecification ).certificateAuthority( tppPolicy.certificateAuthority() );

        //resolving org/orgs
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::organization)) {
            case NORMAL:
                getSubjectFromPolicySpecification(policySpecification).orgs(tppPolicy.organization().values());
                break;
            case DEFAULT:
                getDefaultsSubjectFromPolicySpecification( policySpecification ).org( tppPolicy.organization().values()[0] );
        }

        //resolving orgUnits
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::organizationalUnit)) {
            case NORMAL:
                getSubjectFromPolicySpecification(policySpecification).orgUnits(tppPolicy.organizationalUnit().values());
                break;
            case DEFAULT:
                getDefaultsSubjectFromPolicySpecification( policySpecification ).orgUnits( tppPolicy.organizationalUnit().values() );
        }

        //resolving localities/locality
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::city)) {
            case NORMAL:
                getSubjectFromPolicySpecification( policySpecification ).localities(tppPolicy.city().values());
                break;
            case DEFAULT:
                getDefaultsSubjectFromPolicySpecification(policySpecification).locality(tppPolicy.city().values()[0]);
        }

        //resolving state/states
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::state)) {
            case NORMAL:
                getSubjectFromPolicySpecification( policySpecification ).states(tppPolicy.state().values());
                break;
            case DEFAULT:
                getDefaultsSubjectFromPolicySpecification(policySpecification).state(tppPolicy.state().values()[0]);
        }

        //resolving country/countries
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::country)) {
            case NORMAL:
                getSubjectFromPolicySpecification( policySpecification ).countries(tppPolicy.country().values());
                break;
            case DEFAULT:
                getDefaultsSubjectFromPolicySpecification(policySpecification).country(tppPolicy.country().values()[0]);
        }

        //resolve key pair's attributes

        //resolve keyTypes
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::keyAlgorithm)) {
            case NORMAL:
                getKeyPairFromPolicySpecification( policySpecification ).keyTypes( tppPolicy.keyAlgorithm().values() );
                break;
            case DEFAULT:
                getDefaultsKeyPairFromPolicySpecification(policySpecification).keyType( tppPolicy.keyAlgorithm().values()[0] );
        }

        //resolve rsaKeySizes
        Integer[] keyBitStrength;
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::keyBitStrength)) {
            case NORMAL:
                keyBitStrength = Stream.of( tppPolicy.keyBitStrength().values() ).mapToInt( Integer::parseInt ).boxed().toArray( Integer[]::new );
                getKeyPairFromPolicySpecification( policySpecification ).rsaKeySizes( keyBitStrength );
                break;
            case DEFAULT:
                keyBitStrength = Stream.of( tppPolicy.keyBitStrength().values() ).mapToInt( Integer::parseInt ).boxed().toArray( Integer[]::new );
                getDefaultsKeyPairFromPolicySpecification(policySpecification).rsaKeySize( keyBitStrength[0] );
        }

        //resolve ellipticCurves
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::ellipticCurve)) {
            case NORMAL:
                getKeyPairFromPolicySpecification( policySpecification ).ellipticCurves( tppPolicy.ellipticCurve().values() );
                break;
            case DEFAULT:
                getDefaultsKeyPairFromPolicySpecification(policySpecification).ellipticCurve( tppPolicy.ellipticCurve().values()[0] );
        }

        //resolve serviceGenerated
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::manualCsr)) {
            case NORMAL:
                getKeyPairFromPolicySpecification( policySpecification ).serviceGenerated( tppPolicy.manualCsr().values()[0].equals("0") );
                break;
            case DEFAULT:
                getDefaultsKeyPairFromPolicySpecification(policySpecification).serviceGenerated( tppPolicy.manualCsr().values()[0].equals("0") );
        }

        //resolve reuseAllowed, as on tpp this value represents: Allow Private Key Reuse Want Renewal
        //so if one of these two values is set then apply the value to  ReuseAllowed
        if ( shouldCreateAttribute(tppPolicy, TPPPolicy::allowPrivateKeyReuse) == TypePSAttToCreate.NORMAL )
                getKeyPairFromPolicySpecification( policySpecification ).reuseAllowed( tppPolicy.allowPrivateKeyReuse().values()[0].equals("1") );
            else
                if( shouldCreateAttribute(tppPolicy, TPPPolicy::wantRenewal) == TypePSAttToCreate.NORMAL )
                    getKeyPairFromPolicySpecification( policySpecification ).reuseAllowed( tppPolicy.wantRenewal().values()[0].equals("1") );

        //resolve subjectAltNames
        resolveSubjectAltNames(tppPolicy, policySpecification);

        return policySpecification;
    }

    private static void resolveSubjectAltNames(TPPPolicy tppPolicy, PolicySpecification policySpecification) throws Exception{
        if( tppPolicy.prohibitedSANTypes() != null && tppPolicy.prohibitedSANTypes().length > 0 ) {

            SubjectAltNames subjectAltNames = getSubjectAltNamesFromPolicySpecification( policySpecification );

            //getting the whole list of AltName enum
            List<AltName> allowedAltNames = new ArrayList<>( Arrays.asList( AltName.values() ));

            //filtering the list to leave only the ones which are not in the prohibitedSANTypes list
            Arrays.asList( tppPolicy.prohibitedSANTypes() ).stream().forEach( s -> allowedAltNames.remove(AltName.from(s)));

            for (AltName altName : allowedAltNames) {
                switch ( altName ){
                    case DNS :
                        subjectAltNames.dnsAllowed( Boolean.valueOf(true) );
                        break;
                    case IP :
                        subjectAltNames.ipAllowed( Boolean.valueOf(true) );
                        break;
                    case EMAIL :
                        subjectAltNames.emailAllowed( Boolean.valueOf(true) );
                        break;
                    case URI :
                        subjectAltNames.uriAllowed( Boolean.valueOf(true) );
                        break;
                    case UPN :
                        subjectAltNames.upnAllowed( Boolean.valueOf(true) );
                        break;
                }
            }
        }
    }

    enum TypePSAttToCreate {
        NORMAL, DEFAULT, NONE;
    }

    private static <S> TypePSAttToCreate shouldCreateAttribute(S source, Function<S, AttributeLockable> sourceGetter){
        AttributeLockable<String> attributeLockable = sourceGetter.apply(source);

        if (attributeLockable != null && attributeLockable.values().length > 0 ) {
            if (attributeLockable.lock() )
                return TypePSAttToCreate.NORMAL;
            else
                return TypePSAttToCreate.DEFAULT;
        }

        return TypePSAttToCreate.NONE;
    }

    private static <N, P> N getNestedObject(P parent, Function<P, N> getter, BiConsumer<P, N> setter, Class<N> clazz) throws Exception{
        N nested = getter.apply(parent);

        if ( nested == null) {
            nested = clazz.newInstance();
            setter.accept(parent , nested);
        }

        return nested;
    }

    private static Policy getPolicyFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getNestedObject(policySpecification, PolicySpecification::policy, PolicySpecification::policy, Policy.class);
    }

    private static Subject getSubjectFromPolicy( Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::subject, Policy::subject, Subject.class);
    }

    private static Subject getSubjectFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    private static KeyPair getKeyPairFromPolicy( Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::keyPair, Policy::keyPair, KeyPair.class);
    }

    private static KeyPair getKeyPairFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getKeyPairFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    private static SubjectAltNames getSubjectAltNamesFromPolicy( Policy policy ) throws Exception {
        return getNestedObject(policy, Policy::subjectAltNames, Policy::subjectAltNames, SubjectAltNames.class);
    }

    private static SubjectAltNames getSubjectAltNamesFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectAltNamesFromPolicy(getPolicyFromPolicySpecification(policySpecification));
    }

    private static Defaults getDefaultsFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getNestedObject(policySpecification, PolicySpecification::defaults, PolicySpecification::defaults, Defaults.class);
    }

    private static DefaultsSubject getSubjectFromDefaults( Defaults defaults ) throws Exception {
        return getNestedObject(defaults, Defaults::subject, Defaults::subject, DefaultsSubject.class);
    }

    private static DefaultsSubject getDefaultsSubjectFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getSubjectFromDefaults(getDefaultsFromPolicySpecification(policySpecification));
    }

    private static DefaultsKeyPair getKeyPairFromDefaults( Defaults defaults ) throws Exception {
        return getNestedObject(defaults, Defaults::keyPair, Defaults::keyPair, DefaultsKeyPair.class);
    }

    private static DefaultsKeyPair getDefaultsKeyPairFromPolicySpecification( PolicySpecification policySpecification ) throws Exception {
        return getKeyPairFromDefaults(getDefaultsFromPolicySpecification(policySpecification));
    }
}
