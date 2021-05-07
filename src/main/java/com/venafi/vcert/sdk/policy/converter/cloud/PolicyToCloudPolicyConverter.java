package com.venafi.vcert.sdk.policy.converter.cloud;

import com.venafi.vcert.sdk.certificate.KeySize;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.cloud.CloudConstants;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policy.domain.*;
import com.venafi.vcert.sdk.policy.converter.FromPolicyConverter;
import com.venafi.vcert.sdk.utils.VCertConstants;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PolicyToCloudPolicyConverter implements FromPolicyConverter<CloudPolicy> {

    public static PolicyToCloudPolicyConverter INSTANCE = new PolicyToCloudPolicyConverter();

    private PolicyToCloudPolicyConverter(){}

    public CloudPolicy convertFromPolicy(PolicySpecification policySpecification) throws Exception {

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
    private CloudPolicy.CAInfo getCertAuthorityInfo(Policy policy ) {

        String certificateAuthorityString;

        if( policy != null && policy.certificateAuthority() != null)
            certificateAuthorityString = policy.certificateAuthority();
        else
            certificateAuthorityString = VCertConstants.CLOUD_DEFAULT_CA;

        return new CloudPolicy.CAInfo(certificateAuthorityString);
    }

    private String getValidityPeriod(Policy policy ) {
        int defaultValidDays = 365;
        int maxValidDays;

        if ( policy == null || policy.maxValidDays() == null || (policy.maxValidDays() != null && policy.maxValidDays() == 0)  )
            maxValidDays = defaultValidDays;
        else
            maxValidDays = policy.maxValidDays();

        return "P"+maxValidDays+"D";
    }

    private List<String> convertDomainsToRegex( Policy policy ) {

        List<String> sanRegexList;

        if( policy != null && policy.domains() != null && policy.domains().length > 0){
            sanRegexList = convertToRegex(policy.domains(), policy != null && policy.wildcardAllowed() != null ? policy.wildcardAllowed() : false);
        }else {
            sanRegexList = new ArrayList<>();
            sanRegexList.add(".*");
        }

        return sanRegexList;
    }

    private List<String> convertToRegex( String[] values, boolean wildcardAllowed ) {

        List<String> regexValues = new ArrayList<>();

        for (String current : values ) {
            String currentRegex = StringUtils.replace(current, ".", "\\.");//current.replaceAll( "\\.", "\\.");
            String wildCard = wildcardAllowed ? "*" : "";
            regexValues.add( String.format("[%sA-Za-z]{1}[A-Za-z0-9.-]*\\.", wildCard) + currentRegex );
        }

        return regexValues;
    }

    private List<CertificateIssuingTemplate.AllowedKeyType> getKeyTypes( Policy policy ) {

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

    private CertificateIssuingTemplate.AllowedKeyType getDefaultKeyType( Defaults defaults ) {

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

    private String getCloudDefaultKeyType(){
        return KeyType.RSA.value().toUpperCase(); //it's needed to convert to UpperCase due Cloud only accepts it on that way.
    }

    private List<Integer> getCloudDefaultKeySizes(){
        List<Integer> keySizes = new ArrayList<>();
        keySizes.add(KeySize.KS2048.value());
        return keySizes;
    }

    private CertificateIssuingTemplate.RecommendedSettings getRecommendedSettings( CertificateIssuingTemplate certificateIssuingTemplate ) {
        if (certificateIssuingTemplate.recommendedSettings() == null)
            certificateIssuingTemplate.recommendedSettings( new CertificateIssuingTemplate.RecommendedSettings());
        return certificateIssuingTemplate.recommendedSettings();
    }

    private CertificateIssuingTemplate.RecommendedSettingsKey getRecommendedSettingsKey( CertificateIssuingTemplate certificateIssuingTemplate ) {
        CertificateIssuingTemplate.RecommendedSettingsKey key = getRecommendedSettings(certificateIssuingTemplate).key();
        if(key == null) {
            key = new CertificateIssuingTemplate.RecommendedSettingsKey();
            getRecommendedSettings(certificateIssuingTemplate).key( key );
        }

        return key;
    }
}
