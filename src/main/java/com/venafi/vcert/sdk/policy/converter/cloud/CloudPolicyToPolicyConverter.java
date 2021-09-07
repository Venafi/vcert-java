package com.venafi.vcert.sdk.policy.converter.cloud;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policy.domain.Policy;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

import com.venafi.vcert.sdk.policy.converter.ToPolicyConverterAbstract;

import java.util.ArrayList;
import java.util.List;

public class CloudPolicyToPolicyConverter extends ToPolicyConverterAbstract<CloudPolicy> {
	
	private static final String REGEX = "[a-z]{1}[a-z0-9.-]*\\.";
	private static final String REGEX_WITH_WILCARD = "[*a-z]{1}[a-z0-9.-]*\\.";

    public static CloudPolicyToPolicyConverter INSTANCE = new CloudPolicyToPolicyConverter();

    private CloudPolicyToPolicyConverter(){}

    public PolicySpecification convertToPolicy(CloudPolicy cloudPolicy) throws Exception {
        PolicySpecification policySpecification = new PolicySpecification();

        CertificateIssuingTemplate cit = cloudPolicy.certificateIssuingTemplate();

        policySpecification.name( cit.name() );

        processPolicy( policySpecification, cloudPolicy);

        processDefaults( policySpecification, cloudPolicy);

        return policySpecification;
    }

    private void processPolicy( PolicySpecification policySpecification, CloudPolicy cloudPolicy) throws Exception {

        CertificateIssuingTemplate cit = cloudPolicy.certificateIssuingTemplate();

        processDomainsAndWildcard( policySpecification, cit);
        processMaxValidDays( policySpecification, cit);
        processCertificateAuthority( policySpecification, cloudPolicy.caInfo());

        processSubject( policySpecification, cloudPolicy);

        processKeyPair( policySpecification, cloudPolicy);

        processSubjectAltNames( policySpecification, cloudPolicy);
    }

    private void processDomainsAndWildcard( PolicySpecification policySpecification, CertificateIssuingTemplate cit ) throws Exception{

        List<String> subjectCNRegexes = cit.subjectCNRegexes;
        if ( subjectCNRegexes != null && subjectCNRegexes.size() > 0 && !subjectCNRegexes.get(0).equals(".*") ) {

            Policy policy = getPolicyFromPolicySpecification( policySpecification );
            
            processDomains(policy, subjectCNRegexes);

            processWildcard(policy, subjectCNRegexes);

        } else {
            //domains will not set
        }
    }
    
    private void processDomains( Policy policy, List<String> subjectCNRegexes) {
    	//converting the subjectCNRegexes to domains
        List<String> domains = new ArrayList<String>();
        for (String domain : subjectCNRegexes) {
        	if(domain.startsWith(REGEX_WITH_WILCARD))
        		domain = domain.substring(REGEX_WITH_WILCARD.length());
        	else
        		if(domain.startsWith(REGEX))
            		domain = domain.substring(REGEX.length());
        	
			domain = domain.replace("\\.", ".");
			
			domains.add(domain);
		}
        policy.domains( domains.toArray(new String[0]) );
    }
    
    private void processWildcard( Policy policy, List<String> subjectCNRegexes ) {
    	boolean wildcardFound = false;
        boolean wildcardNotFound = false;
        for ( String subjectCNRegex : subjectCNRegexes) {
            if ( subjectCNRegex.startsWith("[*"))
                wildcardFound = true;
            else
                wildcardNotFound = true;
        }

        if ( wildcardFound && !wildcardNotFound )
            policy.wildcardAllowed(true);
        else
        if ( !wildcardFound && wildcardNotFound )
            policy.wildcardAllowed(false);
    }

    private void processMaxValidDays( PolicySpecification policySpecification,CertificateIssuingTemplate cit ) throws Exception {
        if ( cit.validityPeriod() != null ) {
            String validityPeriod = cit.validityPeriod();
            if ( validityPeriod.matches("P[0-9]*D")) {
                getPolicyFromPolicySpecification( policySpecification ).maxValidDays( Integer.valueOf( validityPeriod.substring(1, validityPeriod.length()-1)) );
            }
        }
    }

    private void processCertificateAuthority( PolicySpecification policySpecification, CloudPolicy.CAInfo caInfo ) throws Exception {
        if ( caInfo != null ) {
            getPolicyFromPolicySpecification( policySpecification ).certificateAuthority( caInfo.certificateAuthorityString() );
        }
    }

    private void processSubject( PolicySpecification policySpecification, CloudPolicy cloudPolicy) throws Exception {
        CertificateIssuingTemplate cit = cloudPolicy.certificateIssuingTemplate();

        if (cit.subjectORegexes() != null)
            getSubjectFromPolicySpecification( policySpecification ).orgs( cit.subjectORegexes.toArray(new String[0]));

        if (cit.subjectOURegexes() != null)
            getSubjectFromPolicySpecification( policySpecification ).orgUnits( cit.subjectOURegexes.toArray(new String[0]));

        if (cit.subjectLRegexes() != null)
            getSubjectFromPolicySpecification( policySpecification ).localities( cit.subjectLRegexes.toArray(new String[0]));

        if (cit.subjectSTRegexes() != null)
            getSubjectFromPolicySpecification( policySpecification ).states( cit.subjectSTRegexes.toArray(new String[0]));

        if (cit.subjectCValues() != null)
            getSubjectFromPolicySpecification( policySpecification ).countries( cit.subjectCValues.toArray(new String[0]));
    }

    private void processKeyPair( PolicySpecification policySpecification, CloudPolicy cloudPolicy) throws Exception {
        CertificateIssuingTemplate cit = cloudPolicy.certificateIssuingTemplate();

        if ( cit.keyReuse() != null )
            getKeyPairFromPolicySpecification( policySpecification ).reuseAllowed( cit.keyReuse() );

        if ( cit.keyTypes() != null && cit.keyTypes().size() > 0)
            processKeyTypes(policySpecification, cit.keyTypes().get(0));
    }

    private void processKeyTypes( PolicySpecification policySpecification, CertificateIssuingTemplate.AllowedKeyType keyType) throws Exception {

        if( keyType.keyType() != null ) {
            String[] keyTypes = { keyType.keyType() };
            getKeyPairFromPolicySpecification( policySpecification ).keyTypes( keyTypes );
        }

        if( keyType.keyLengths() != null && keyType.keyLengths().size() > 0 ) {
            getKeyPairFromPolicySpecification( policySpecification ).rsaKeySizes( keyType.keyLengths().toArray( new Integer[0]) );
        }
    }

    private void processSubjectAltNames( PolicySpecification policySpecification, CloudPolicy cloudPolicy) throws Exception {
        processSubjectAltNames( policySpecification, cloudPolicy.certificateIssuingTemplate());
    }

    private void processSubjectAltNames(PolicySpecification policySpecification, CertificateIssuingTemplate cit ) throws Exception {

        List<String> subjectCNRegexes = cit.sanDnsNameRegexes();
        if (subjectCNRegexes != null && subjectCNRegexes.size() > 0 && !subjectCNRegexes.get(0).equals(".*"))
            getSubjectAltNamesFromPolicySpecification(policySpecification).dnsAllowed(true);
    }

    private void processDefaults( PolicySpecification policySpecification, CloudPolicy cloudPolicy ) throws Exception {
        if ( cloudPolicy.certificateIssuingTemplate().recommendedSettings() != null ) {

            CertificateIssuingTemplate.RecommendedSettings recommendedSettings = cloudPolicy.certificateIssuingTemplate().recommendedSettings();

            processDefaultsSubject( policySpecification, recommendedSettings);

            processDefaultsKeyPair( policySpecification, recommendedSettings);
        }
    }

    private void processDefaultsSubject( PolicySpecification policySpecification, CertificateIssuingTemplate.RecommendedSettings recommendedSettings ) throws Exception {
        if ( recommendedSettings.subjectOValue() != null )
            getDefaultsSubjectFromPolicySpecification( policySpecification ).org( recommendedSettings.subjectOValue() );

        if ( recommendedSettings.subjectOUValue() != null ) {
            String[] subjectOUValues = {recommendedSettings.subjectOUValue()};
            getDefaultsSubjectFromPolicySpecification(policySpecification).orgUnits(subjectOUValues);
        }

        if ( recommendedSettings.subjectLValue() != null )
            getDefaultsSubjectFromPolicySpecification( policySpecification ).locality( recommendedSettings.subjectLValue() );

        if ( recommendedSettings.subjectSTValue() != null )
            getDefaultsSubjectFromPolicySpecification( policySpecification ).state( recommendedSettings.subjectSTValue() );

        if ( recommendedSettings.subjectCValue() != null )
            getDefaultsSubjectFromPolicySpecification( policySpecification ).country( recommendedSettings.subjectCValue() );
    }

    private void processDefaultsKeyPair( PolicySpecification policySpecification, CertificateIssuingTemplate.RecommendedSettings recommendedSettings) throws Exception {
        processDefaultsKeyType( policySpecification, recommendedSettings);
    }

    private void processDefaultsKeyType( PolicySpecification policySpecification, CertificateIssuingTemplate.RecommendedSettings recommendedSettings) throws Exception {

        if( recommendedSettings.key() != null ) {
            if( recommendedSettings.key().type() != null )
                getDefaultsKeyPairFromPolicySpecification(policySpecification).keyType(recommendedSettings.key().type());

            if( recommendedSettings.key().length() != null )
                getDefaultsKeyPairFromPolicySpecification(policySpecification).rsaKeySize(recommendedSettings.key().length());
        }
    }

}