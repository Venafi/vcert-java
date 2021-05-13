package com.venafi.vcert.sdk.policy.converter.tpp;

import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;
import com.venafi.vcert.sdk.policy.domain.SubjectAltNames;
import com.venafi.vcert.sdk.policy.converter.ToPolicyConverterAbstract;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class TppPolicyToPolicyConverter extends ToPolicyConverterAbstract<TPPPolicy> {

    public static TppPolicyToPolicyConverter INSTANCE = new TppPolicyToPolicyConverter();

    private TppPolicyToPolicyConverter(){}

    public PolicySpecification convertToPolicy(TPPPolicy tppPolicy ) throws Exception {
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

        //resolving management type
        switch (shouldCreateAttribute(tppPolicy, TPPPolicy::managementType)) {
            case NORMAL:
                getPolicyFromPolicySpecification(policySpecification).autoInstalled( ManagementTypes.from( tppPolicy.managementType().values()[0]).psValue );
                break;
        }

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
        if ( shouldCreateAttribute(tppPolicy, TPPPolicy::allowPrivateKeyReuse) == TypePSAToCreate.NORMAL )
            getKeyPairFromPolicySpecification( policySpecification ).reuseAllowed( tppPolicy.allowPrivateKeyReuse().values()[0].equals("1") );
        else
        if( shouldCreateAttribute(tppPolicy, TPPPolicy::wantRenewal) == TypePSAToCreate.NORMAL )
            getKeyPairFromPolicySpecification( policySpecification ).reuseAllowed( tppPolicy.wantRenewal().values()[0].equals("1") );

        //resolve subjectAltNames
        resolveSubjectAltNames(tppPolicy, policySpecification);

        return policySpecification;
    }

    private void resolveSubjectAltNames(TPPPolicy tppPolicy, PolicySpecification policySpecification) throws Exception{
        if( tppPolicy.prohibitedSANTypes() != null && tppPolicy.prohibitedSANTypes().length > 0 ) {

            SubjectAltNames subjectAltNames = getSubjectAltNamesFromPolicySpecification( policySpecification );

            //getting the whole list of AltName enum
            List<AltName> allowedAltNames = new ArrayList<>( Arrays.asList( AltName.values() ));

            //filtering the list to leave only the ones which are not in the prohibitedSANTypes list
            Arrays.asList( tppPolicy.prohibitedSANTypes() ).stream().forEach( s -> allowedAltNames.remove(AltName.from(s)));

            for (AltName altName : allowedAltNames) {
                switch ( altName ){
                    case DNS :
                        subjectAltNames.dnsAllowed( Boolean.valueOf(false) );
                        break;
                    case IP :
                        subjectAltNames.ipAllowed( Boolean.valueOf(false) );
                        break;
                    case EMAIL :
                        subjectAltNames.emailAllowed( Boolean.valueOf(false) );
                        break;
                    case URI :
                        subjectAltNames.uriAllowed( Boolean.valueOf(false) );
                        break;
                    case UPN :
                        subjectAltNames.upnAllowed( Boolean.valueOf(false) );
                        break;
                }
            }
        }
    }
}
