package com.venafi.vcert.sdk.policyspecification.parser.converter;

import com.venafi.vcert.sdk.certificate.KeySize;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.cloud.CloudConstants;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.policyspecification.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policyspecification.domain.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CloudPolicySpecificationAPIConverter implements IPolicySpecificationAPIConverter<CloudPolicy> {

    public static final CloudPolicySpecificationAPIConverter INSTANCE = new CloudPolicySpecificationAPIConverter();

    private CloudPolicyToPolicySpecificationConverter cloudPolicyToPolicySpecificationConverter;

    private CloudPolicySpecificationAPIConverter(){
        this.cloudPolicyToPolicySpecificationConverter = new CloudPolicyToPolicySpecificationConverter();
    }

    @Override
    public CloudPolicy convert(PolicySpecification policySpecification) throws Exception {
        return PolicySpecificationToCloudPolicyConverter.convert( policySpecification );
    }

    @Override
    public PolicySpecification convert(CloudPolicy cloudPolicy) throws Exception {
        return cloudPolicyToPolicySpecificationConverter.convert( cloudPolicy );
    }
}

class PolicySpecificationToCloudPolicyConverter {

    public static CloudPolicy convert(PolicySpecification policySpecification) throws Exception {

        CloudPolicy cloudPolicy = new CloudPolicy();

        Policy policy = policySpecification.policy();

        CloudPolicy.CAInfo caInfo = getCertAuthorityInfo(policy);
        cloudPolicy.caInfo( caInfo );

        CertificateIssuingTemplate cit = new CertificateIssuingTemplate();

        cloudPolicy.certificateIssuingTemplate(cit);

        cit.certificateAuthority(caInfo.caType());

        cit.product( new CertificateIssuingTemplate.Product(caInfo.caType(), caInfo.vendorProductName(), getValidityPeriod( policy ), null, null, null) );

        switch ( caInfo.caType().toUpperCase() ) {
            case CloudConstants.ENTRUST_TYPE:
                cit.trackingData(CloudConstants.ENTRUST_DEFAULT_TRACKING_DATA);
                break;
            case CloudConstants.DIGICERT_TYPE:
                CertificateIssuingTemplate.Product product = cit.product();
                product.hashAlgorithm("SHA256");
                product.autoRenew(false);
                break;
        }

        List<String> domainsInRegex = convertDomainsToRegex( policy );

        cit.subjectCNRegexes(domainsInRegex);

        if ( policy != null && policy.subjectAltNames() != null && policy.subjectAltNames().dnsAllowed() != null ) {
            if ( policy.subjectAltNames().dnsAllowed() )
                cit.sanDnsNameRegexes(domainsInRegex);
        } else
            cit.sanDnsNameRegexes(domainsInRegex);

        List<String> defaultRegexes = new ArrayList<>();
        defaultRegexes.add(PolicySpecificationConst.ALLOW_ALL);

        if( policy != null && policy.subject() != null ) {
            Subject policySubject = policy.subject();

            cit.subjectORegexes( (policySubject.orgs() != null && policySubject.orgs().length > 0 ) ? Arrays.asList( policySubject.orgs() ) : defaultRegexes);
            cit.subjectOURegexes( ( policySubject.orgUnits() != null && policySubject.orgUnits().length > 0 ) ? Arrays.asList( policySubject.orgUnits() ) : defaultRegexes);
            cit.subjectLRegexes( ( policySubject.localities() != null && policySubject.localities().length > 0 ) ? Arrays.asList( policySubject.localities() ) : defaultRegexes);
            cit.subjectSTRegexes( ( policySubject.states() != null && policySubject.states().length > 0 ) ? Arrays.asList( policySubject.states() ) : defaultRegexes);
            cit.subjectCValues( ( policySubject.countries() != null && policySubject.countries().length > 0 ) ? Arrays.asList( policySubject.countries() ) : defaultRegexes);
        } else {
            cit.subjectORegexes( defaultRegexes );
            cit.subjectOURegexes( defaultRegexes );
            cit.subjectLRegexes( defaultRegexes );
            cit.subjectSTRegexes( defaultRegexes );
            cit.subjectCValues( defaultRegexes );
        }

        cit.keyTypes( getKeyTypes(policy) );
        cit.keyReuse( policy != null && policy.keyPair() != null && policy.keyPair().reuseAllowed() != null ? policy.keyPair().reuseAllowed() : false);

        //build recommended settings

        Defaults defaults = policySpecification.defaults();
        if ( defaults != null && defaults.subject() != null ) {
            DefaultsSubject defaultsSubject = defaults.subject();

            if( defaultsSubject.org() != null )
                getRecommendedSettings(cit).subjectOValue( defaultsSubject.org() );

            if( defaultsSubject.orgUnits() != null )
                getRecommendedSettings(cit).subjectOUValue( defaultsSubject.orgUnits()[0] );

            if( defaultsSubject.locality() != null )
                getRecommendedSettings(cit).subjectLValue( defaultsSubject.locality() );

            if( defaultsSubject.state() != null )
                getRecommendedSettings(cit).subjectSTValue( defaultsSubject.state() );

            if( defaultsSubject.country() != null )
                getRecommendedSettings(cit).subjectCValue( defaultsSubject.country() );
        }

        if ( defaults != null && defaults.keyPair() != null ) {
            CertificateIssuingTemplate.AllowedKeyType recommendedKey = getDefaultKeyType( defaults );

            CertificateIssuingTemplate.RecommendedSettingsKey key = getRecommendedSettingsKey( cit );

            key.type(recommendedKey.keyType());
            key.length(recommendedKey.keyLengths().get(0));
        }

        return cloudPolicy;
    }

    /**
     *
     * @param policy
     * @return An array of 3 Strings where each one of them represents the following: [0] = CAType,  [1] = CAAccountKey and [2] = VendorProductName
     *
     */
    private static CloudPolicy.CAInfo getCertAuthorityInfo(Policy policy ) {

        String certificateAuthorityString;

        if( policy != null && policy.certificateAuthority() != null)
            certificateAuthorityString = policy.certificateAuthority();
        else
            certificateAuthorityString = CloudConstants.DEFAULT_PRODUCT;

        return new CloudPolicy.CAInfo(certificateAuthorityString);
    }

    private static String getValidityPeriod(Policy policy ) {
        int defaultValidDays = 365;
        int maxValidDays;

        if ( policy == null || policy.maxValidDays() == null || (policy.maxValidDays() != null && policy.maxValidDays() == 0)  )
            maxValidDays = defaultValidDays;
        else
            maxValidDays = policy.maxValidDays();

        return "P"+maxValidDays+"D";
    }

    private static List<String> convertDomainsToRegex( Policy policy ) {

        List<String> sanRegexList;

        if( policy != null && policy.domains() != null && policy.domains().length > 0){
            sanRegexList = convertToRegex(policy.domains(), policy != null && policy.wildcardAllowed() != null ? policy.wildcardAllowed() : false);
        }else {
            sanRegexList = new ArrayList<>();
            sanRegexList.add(".*");
        }

        return sanRegexList;
    }

    private static List<String> convertToRegex( String[] values, boolean wildcardAllowed ) {

        List<String> regexValues = new ArrayList<>();

        for (String current : values ) {
            String currentRegex = current.replaceAll( "\\.", "\\.");
            String wildCard = wildcardAllowed ? "*" : "";
            regexValues.add( String.format("[%sA-Za-z]{1}[A-Za-z0-9.-]*\\.", wildCard) + currentRegex );
        }

        return regexValues;
    }

    private static List<CertificateIssuingTemplate.AllowedKeyType> getKeyTypes( Policy policy ) {

        List<CertificateIssuingTemplate.AllowedKeyType> keyTypes = new ArrayList<>();

        //creating the default KeyType attributes
        String keyType = getCloudDefaultKeyType();
        List<Integer> keySizes = getCloudDefaultKeySizes();

        if ( policy != null && policy.keyPair() != null ) {
            if (policy.keyPair().keyTypes()[0] != null)
                keyType = policy.keyPair().keyTypes()[0].toUpperCase();//it's needed to convert to UpperCase due Cloud only accepts it on that way.
            if (policy.keyPair().rsaKeySizes() != null)
                keySizes = Arrays.asList(policy.keyPair().rsaKeySizes());
        }

        keyTypes.add( new CertificateIssuingTemplate.AllowedKeyType(keyType, keySizes) );
        return keyTypes;
    }

    private static CertificateIssuingTemplate.AllowedKeyType getDefaultKeyType( Defaults defaults ) {

        //creating the default KeyType attributes
        String keyType = getCloudDefaultKeyType();
        List<Integer> keySizes = getCloudDefaultKeySizes();

        if ( defaults != null && defaults.keyPair() != null ) {
            if (defaults.keyPair().keyType() != null)
                keyType = defaults.keyPair().keyType().toUpperCase();//it's needed to convert to UpperCase due Cloud only accepts it on that way
            if (defaults.keyPair().rsaKeySize() != null)
                keySizes = Arrays.asList(defaults.keyPair().rsaKeySize());
        }

        return new CertificateIssuingTemplate.AllowedKeyType(keyType, keySizes);
    }

    private static String getCloudDefaultKeyType(){
        return KeyType.RSA.value().toUpperCase(); //it's needed to convert to UpperCase due Cloud only accepts it on that way.
    }

    private static List<Integer> getCloudDefaultKeySizes(){
        List<Integer> keySizes = new ArrayList<>();
        keySizes.add(KeySize.KS2048.value());
        return keySizes;
    }

    private static CertificateIssuingTemplate.RecommendedSettings getRecommendedSettings( CertificateIssuingTemplate certificateIssuingTemplate ) {
        if (certificateIssuingTemplate.recommendedSettings() == null)
            certificateIssuingTemplate.recommendedSettings( new CertificateIssuingTemplate.RecommendedSettings());
        return certificateIssuingTemplate.recommendedSettings();
    }

    private static CertificateIssuingTemplate.RecommendedSettingsKey getRecommendedSettingsKey( CertificateIssuingTemplate certificateIssuingTemplate ) {
        CertificateIssuingTemplate.RecommendedSettingsKey key = getRecommendedSettings(certificateIssuingTemplate).key();
        if(key == null) {
            key = new CertificateIssuingTemplate.RecommendedSettingsKey();
            getRecommendedSettings(certificateIssuingTemplate).key( key );
        }

        return key;
    }
}

class CloudPolicyToPolicySpecificationConverter extends PolicySpecificationConverter<CloudPolicy>{

    public PolicySpecification convert(CloudPolicy cloudPolicy) throws Exception {
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
             policy.domains( subjectCNRegexes.toArray(new String[0]) );

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

         } else {
             //domains will not set
         }
    }

    private void processMaxValidDays( PolicySpecification policySpecification,CertificateIssuingTemplate cit ) throws Exception {
        if ( cit.product() != null && cit.product().validityPeriod() != null ) {
            String validityPeriod = cit.product().validityPeriod();
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