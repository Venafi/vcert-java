package com.venafi.vcert.sdk.policyspecification.parser.marshal;

import com.venafi.vcert.sdk.policyspecification.domain.*;
import org.snakeyaml.engine.v2.api.*;

import java.util.List;
import java.util.Map;

public class PolicySpecificationYamlMarshal implements IPolicySpecificationMarshal {

    public static final PolicySpecificationYamlMarshal INSTANCE = new PolicySpecificationYamlMarshal();

    private Load load;

    private PolicySpecificationYamlMarshal(){
        LoadSettings settings = LoadSettings.builder().setLabel("Custom user configuration").build();
        load = new Load(settings);
    }

    @Override
    public PolicySpecification unmarshal(String yamlString) throws VCertMarshalException {

        Object policySpecificationYaml = load.loadFromString(yamlString);

        PolicySpecification policySpecification = loadPolicySpecificationFrom(policySpecificationYaml);

        return policySpecification;
    }

    private PolicySpecification loadPolicySpecificationFrom( Object object) {
        PolicySpecification policySpecification = null;

        if(object instanceof Map){

            Map<String, Object> policySpecificationMap = (Map<String, Object>)object;
            policySpecification = new PolicySpecification();

            if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_NAME))
                policySpecification.name((String)policySpecificationMap.get(PolicySpecificationConst.ATT_NAME));

            if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_OWNERS))
                policySpecification.owners(((List<String>)policySpecificationMap.get(PolicySpecificationConst.ATT_OWNERS)).toArray(new String[0]));

            if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_USERS))
                policySpecification.users(((List<String>)policySpecificationMap.get(PolicySpecificationConst.ATT_USERS)).toArray(new String[0]));

            if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_USER_ACCESS))
                policySpecification.userAccess((String)policySpecificationMap.get(PolicySpecificationConst.ATT_USER_ACCESS));

            if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_APPROVERS))
                policySpecification.approvers(((List<String>)policySpecificationMap.get(PolicySpecificationConst.ATT_APPROVERS)).toArray(new String[0]));

            policySpecification.policy( loadPolicyFrom(policySpecificationMap) );
            policySpecification.defaults( loadDefaultsFrom(policySpecificationMap) );
        }

        return policySpecification;
    }

    private Policy loadPolicyFrom(Map<String, Object> policySpecificationMap){
        Policy policy = null;

        if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_POLICY)) {

            Map<String, Object> policyMap = (Map<String, Object>) policySpecificationMap.get(PolicySpecificationConst.ATT_POLICY);
            policy = new Policy();

            if(policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_DOMAINS))
                policy.domains(((List<String>)policyMap.get(PolicySpecificationConst.ATT_POLICY_DOMAINS)).toArray(new String[0]));

            if(policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_WILDCARD_ALLOWED))
                policy.wildcardAllowed((Boolean)policyMap.get(PolicySpecificationConst.ATT_POLICY_WILDCARD_ALLOWED));

            if(policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_MAX_VALID_DAYS))
                policy.maxValidDays((Integer)policyMap.get(PolicySpecificationConst.ATT_POLICY_MAX_VALID_DAYS));

            if(policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_CERTIFICATE_AUTHORITY))
                policy.certificateAuthority((String)policyMap.get(PolicySpecificationConst.ATT_POLICY_CERTIFICATE_AUTHORITY));

            if(policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_AUTO_INSTALLED))
                policy.autoInstalled((Boolean)policyMap.get(PolicySpecificationConst.ATT_POLICY_AUTO_INSTALLED));

            policy.subject( loadPolicySubjectFrom(policyMap) );
            policy.keyPair( loadPolicyKeyPairFrom(policyMap) );
            policy.subjectAltNames( loadPolicySubjectAlNamesFrom(policyMap) );
        }

        return policy;
    }

    private Subject loadPolicySubjectFrom(Map<String, Object> policyMap){
        Subject subject = null;

        if( policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT) ){
            Map<String, Object> subjectMap = (Map<String, Object>)policyMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT);
            subject = new Subject();

            if(subjectMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS))
                subject.orgs(((List<String>)subjectMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS)).toArray(new String[0]));

            if(subjectMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS))
                subject.orgUnits(((List<String>)subjectMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS)).toArray(new String[0]));

            if(subjectMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES))
                subject.localities(((List<String>)subjectMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES)).toArray(new String[0]));

            if(subjectMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES))
                subject.states(((List<String>)subjectMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES)).toArray(new String[0]));

            if(subjectMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES))
                subject.countries(((List<String>)subjectMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES)).toArray(new String[0]));
        }

        return subject;
    }

    private KeyPair loadPolicyKeyPairFrom(Map<String, Object> policyMap){
        KeyPair keyPair = null;

        if( policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR) ){
            Map<String, Object> keyPairMap = (Map<String, Object>)policyMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR);
            keyPair = new KeyPair();

            if(keyPairMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES))
                keyPair.keyTypes(((List<String>)keyPairMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES)).toArray(new String[0]));

            if(keyPairMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES))
                keyPair.rsaKeySizes(((List<Integer>)keyPairMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES)).toArray(new Integer[0]));

            if(keyPairMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES))
                keyPair.ellipticCurves(((List<String>)keyPairMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES)).toArray(new String[0]));

            if(keyPairMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR_SERVICE_GENERATED_TYPE))
                keyPair.serviceGenerated((Boolean)keyPairMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR_SERVICE_GENERATED_TYPE));

            if(keyPairMap.containsKey(PolicySpecificationConst.ATT_POLICY_KEYPAIR_REUSE_ALLOWED))
                keyPair.reuseAllowed((Boolean)keyPairMap.get(PolicySpecificationConst.ATT_POLICY_KEYPAIR_REUSE_ALLOWED));
        }

        return keyPair;
    }

    private SubjectAltNames loadPolicySubjectAlNamesFrom(Map<String, Object> policyMap){
        SubjectAltNames subjectAltNames = null;

        if( policyMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES) ){
            Map<String, Object> subjectAltNamesMap = (Map<String, Object>)policyMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES);
            subjectAltNames = new SubjectAltNames();

            if(subjectAltNamesMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_DNS_ALLOWED))
                subjectAltNames.dnsAllowed((Boolean)subjectAltNamesMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_DNS_ALLOWED));

            if(subjectAltNamesMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED))
                subjectAltNames.ipAllowed((Boolean)subjectAltNamesMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED));

            if(subjectAltNamesMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED))
                subjectAltNames.emailAllowed((Boolean)subjectAltNamesMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED));

            if(subjectAltNamesMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED))
                subjectAltNames.uriAllowed((Boolean)subjectAltNamesMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED));

            if(subjectAltNamesMap.containsKey(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_UPN_ALLOWED))
                subjectAltNames.upnAllowed((Boolean)subjectAltNamesMap.get(PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_UPN_ALLOWED));
        }

        return subjectAltNames;
    }

    private Defaults loadDefaultsFrom(Map<String, Object> policySpecificationMap){
        Defaults defaults = null;

        if(policySpecificationMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS)) {

            Map<String, Object> defaultsMap = (Map<String, Object>) policySpecificationMap.get(PolicySpecificationConst.ATT_DEFAULTS);
            defaults = new Defaults();

            if(defaultsMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_DOMAIN))
                defaults.domain((String)defaultsMap.get(PolicySpecificationConst.ATT_DEFAULTS_DOMAIN));

            if(defaultsMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_AUTO_INSTALLED))
                defaults.autoInstalled((Boolean)defaultsMap.get(PolicySpecificationConst.ATT_DEFAULTS_AUTO_INSTALLED));

            defaults.subject( loadDefaultsSubjectFrom(defaultsMap) );
            defaults.keyPair( loadDefaultsKeyPairFrom(defaultsMap) );
        }

        return defaults;
    }

    private DefaultsSubject loadDefaultsSubjectFrom(Map<String, Object> defaultsMap){
        DefaultsSubject defaultsSubject = null;

        if( defaultsMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT) ){
            Map<String, Object> defaultsSubjectMap = (Map<String, Object>)defaultsMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT);
            defaultsSubject = new DefaultsSubject();

            if(defaultsSubjectMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG))
                defaultsSubject.org((String)defaultsSubjectMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG));

            if(defaultsSubjectMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS))
                defaultsSubject.orgUnits(((List<String>)defaultsSubjectMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS)).toArray(new String[0]));

            if(defaultsSubjectMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY))
                defaultsSubject.locality((String)defaultsSubjectMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY));

            if(defaultsSubjectMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE))
                defaultsSubject.state((String)defaultsSubjectMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE));

            if(defaultsSubjectMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY))
                defaultsSubject.country((String)defaultsSubjectMap.get(PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY));
        }

        return defaultsSubject;
    }

    private DefaultsKeyPair loadDefaultsKeyPairFrom(Map<String, Object> defaultsMap){
        DefaultsKeyPair defaultsKeyPair = null;

        if( defaultsMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR) ){
            Map<String, Object> defaultsKeyPairMap = (Map<String, Object>)defaultsMap.get(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR);
            defaultsKeyPair = new DefaultsKeyPair();

            if(defaultsKeyPairMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE))
                defaultsKeyPair.keyType((String)defaultsKeyPairMap.get(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE));

            if(defaultsKeyPairMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE))
                defaultsKeyPair.rsaKeySize((Integer)defaultsKeyPairMap.get(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE));

            if(defaultsKeyPairMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_ELLIPTIC_CURVE))
                defaultsKeyPair.ellipticCurve((String)defaultsKeyPairMap.get(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_ELLIPTIC_CURVE));

            if(defaultsKeyPairMap.containsKey(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_SERVICE_GENERATED_TYPE))
                defaultsKeyPair.serviceGenerated((Boolean)defaultsKeyPairMap.get(PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_SERVICE_GENERATED_TYPE));
        }

        return defaultsKeyPair;
    }

    @Override
    public String marshal(PolicySpecification policySpecification) throws VCertMarshalException {
        return null;
    }
}
