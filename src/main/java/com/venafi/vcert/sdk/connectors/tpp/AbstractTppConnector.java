package com.venafi.vcert.sdk.connectors.tpp;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.annotations.SerializedName;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.ServerPolicy;

import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.policyspecification.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policyspecification.parser.converter.AltName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

public abstract class AbstractTppConnector {
    protected static final Pattern POLICY_REGEX = Pattern.compile("^\\\\VED\\\\Policy");
    protected static final String HEADER_VALUE_AUTHORIZATION = "Bearer %s";

    protected static final String FAILED_TO_AUTHENTICATE_MESSAGE = "failed to authenticate: ";
    protected static final String MISSING_CREDENTIALS_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing credentials";
    protected static final String MISSING_REFRESH_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing refresh token";
    protected static final String MISSING_ACCESS_TOKEN_MESSAGE = FAILED_TO_AUTHENTICATE_MESSAGE + "missing access token";
    protected static final String TPP_ATTRIBUTE_MANAGEMENT_TYPE = "Management Type";
    protected static final String TPP_ATTRIBUTE_MANUAL_CSR = "Manual Csr";

    // TODO can be enum
    @SuppressWarnings("serial")
    protected static final Map<String, Integer> revocationReasons = new HashMap<String, Integer>() {
        {
            put("", 0); // NoReason
            put("none", 0); //
            put("key-compromise", 1); // UserKeyCompromised
            put("ca-compromise", 2); // CAKeyCompromised
            put("affiliation-changed", 3); // UserChangedAffiliation
            put("superseded", 4); // CertificateSuperseded
            put("cessation-of-operation", 5); // OriginalUseNoLongerValid
        }
    };

    protected final Tpp tpp;

    @Getter
    protected String zone;
    protected String vendorAndProductName;

    protected TppAPI tppAPI;

    public AbstractTppConnector(Tpp tpp) {

        this.tpp = tpp;
        this.tppAPI = getTppAPI();
    }

    protected abstract TppAPI getTppAPI();

    @VisibleForTesting
    String getPolicyDN(final String zone) {
        String result = zone;
        Matcher candidate = POLICY_REGEX.matcher(zone);
        if (!candidate.matches()) {
            if (!POLICY_REGEX.matcher(zone).matches()) {
                result = "\\" + result;
            }
            result = "\\VED\\Policy" + result;
        }
        return result;
    }

    public void setPolicy(String policyName, TPPPolicy tppPolicy) throws VCertException {

        //ensuring that the policy name starts with the tpp_root_path
        if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
            policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

        tppPolicy.policyName( policyName );

        //if the policy doesn't exist
        if(!dnExist(policyName)){

            //verifying that the policy's parent exists
            String parentName = tppPolicy.getParentName();
            if(!parentName.equals(TppPolicyConstants.TPP_ROOT_PATH) && !dnExist(parentName))
                throw new VCertException("The policy's parent doesn't exist");

            //creating the policy
            createPolicy( policyName );
        }

        //creating policy's attributes.
        setPolicyAttributes(tppPolicy);
    }

    protected abstract String getAuthKey() throws VCertException;

    protected boolean dnExist(String dn) throws VCertException {
        try {
            DNIsValidResponse dnIsValidResponse = tppAPI.dnIsValid(new DNIsValidRequest(dn), getAuthKey());

            if(dnIsValidResponse.result() == 1 && dnIsValidResponse.objectDN().dn()!=null)
                return true;
            else
                if( dnIsValidResponse.error() != null && dnIsValidResponse.result() == 400)
                    return false;
                else
                    throw new VCertException(dnIsValidResponse.error());
        } catch (Exception e) {
            throw new VCertException(e);
        }
    }

    private void createPolicy(String dn) throws VCertException {
        try {
            CreateDNResponse createDNResponse = tppAPI.createDN(new CreateDNRequest(dn), getAuthKey());

            if( createDNResponse.error() != null)// && createDNResponse.result() == 401)
                throw new VCertException(createDNResponse.error());
        } catch (Exception e) {
            throw new VCertException(e);
        }
    }

    private void setPolicyAttributes(TPPPolicy tppPolicy) throws VCertException {
        //create Contact
        if (tppPolicy.contact() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CONTACT, tppPolicy.contact(), true);

        //create Approver
        if (tppPolicy.approver() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_APPROVER, tppPolicy.approver(), true);

        //create Domain Suffix Whitelist
        if (tppPolicy.domainSuffixWhiteList() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_DOMAIN_SUFFIX_WHITELIST, tppPolicy.domainSuffixWhiteList(), true);

        //create Prohibit Wildcard
        if (tppPolicy.prohibitWildcard() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_PROHIBIT_WILDCARD, new Integer[]{tppPolicy.prohibitWildcard()}, false);

        //create Certificate Authority
        if (tppPolicy.certificateAuthority() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CERTIFICATE_AUTHORITY, new String[]{tppPolicy.certificateAuthority()}, false);

        //create Organization attribute
        if (tppPolicy.organization() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATION, tppPolicy.organization().values(), tppPolicy.organization().lock());

        //TODO Confirm with Angel if this attribute is lockeable or not
        //create Organizational Unit attribute
        if (tppPolicy.organizationalUnit() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATIONAL_UNIT, tppPolicy.organizationalUnit().values(), tppPolicy.organizationalUnit().lock());

        //create City attribute
        if (tppPolicy.city() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CITY, tppPolicy.city().values(), tppPolicy.city().lock());

        //create State attribute
        if (tppPolicy.state() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_STATE, tppPolicy.state().values(), tppPolicy.state().lock());

        //create Country attribute
        if (tppPolicy.country() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_COUNTRY, tppPolicy.country().values(), tppPolicy.country().lock());

        //create Key Algorithm attribute
        if (tppPolicy.keyAlgorithm() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_ALGORITHM, tppPolicy.keyAlgorithm().values(), tppPolicy.keyAlgorithm().lock());

        //create Key Bit Strength
        if (tppPolicy.keyBitStrength() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_BIT_STRENGTH, tppPolicy.keyBitStrength().values(), tppPolicy.keyBitStrength().lock());

        //create Elliptic Curve attribute
        if (tppPolicy.ellipticCurve() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ELLIPTIC_CURVE, tppPolicy.ellipticCurve().values(), tppPolicy.ellipticCurve().lock());

        //create Manual Csr attribute
        if (tppPolicy.manualCsr() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_MANUAL_CSR, tppPolicy.manualCsr().values(), tppPolicy.manualCsr().lock());

        //create prohibited SAN Types attribute
        if (tppPolicy.prohibitedSANTypes() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_PROHIBITED_SAN_TYPES, tppPolicy.prohibitedSANTypes(), false);

        //TODO Confirm with Angel if this attribute is lockeable or not
        //Allow Private Key Reuse" & "Want Renewal
        if (tppPolicy.allowPrivateKeyReuse() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ALLOW_PRIVATE_KEY_REUSE, tppPolicy.allowPrivateKeyReuse().values(), tppPolicy.allowPrivateKeyReuse().lock());

        //TODO Confirm with Angel if this attribute is lockeable or not
        //create Want Renewal attribute
        if (tppPolicy.wantRenewal() != null)
            setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_WANT_RENEWAL, tppPolicy.wantRenewal().values(), tppPolicy.wantRenewal().lock());
    }

    private void setPolicyAttribute(String dn, String attributeName, Object[] values, boolean locked) throws VCertException {
        try {
            SetPolicyAttributeResponse setPolicyAttributeResponse = tppAPI.setPolicyAttribute(new SetPolicyAttributeRequest(dn, attributeName, values, locked), getAuthKey());

            if(setPolicyAttributeResponse.result() != 1)
                throw new VCertException(setPolicyAttributeResponse.error());
        } catch (Exception e) {
            throw new VCertException(e);
        }
    }

    public TPPPolicy getPolicy(String policyName) throws VCertException {

        TPPPolicy tppPolicy = new TPPPolicy();

        //ensuring that the policy name starts with the tpp_root_path
        if (!policyName.startsWith(TppPolicyConstants.TPP_ROOT_PATH))
            policyName = TppPolicyConstants.TPP_ROOT_PATH + policyName;

        //if the policy doesn't exist
        //if(!dnExist(policyName))
        //    throw new VCertException("The specified policy doesn't exist");

        tppPolicy.policyName( policyName );

        //populating the tppPolicy
        populatePolicy(tppPolicy);

        return tppPolicy;
    }

    private TPPPolicy populatePolicy(TPPPolicy tppPolicy) throws VCertException {
        GetPolicyResponse getPolicyResponse = null;
        try {
            getPolicyResponse = tppAPI.getPolicy(new GetPolicyRequest(tppPolicy.policyName()), getAuthKey());
        } catch (Exception e) {
            throw new VCertException(e);
        }

        if(getPolicyResponse != null && getPolicyResponse.error() != null)
            throw new VCertException(getPolicyResponse.error());

        // Contact
        //tppPolicy.contact( getAttributeValues( tppPolicy.policyName(), TppPolicyConstants.TPP_CONTACT, String.class));

        // Approver
        //tppPolicy.approver( getAttributeValues( tppPolicy.policyName(), TppPolicyConstants.TPP_APPROVER, String.class));

        PolicyResponse policyResponse = getPolicyResponse.policy();

        if ( policyResponse != null ){
            //Domain suffix white list
            tppPolicy.domainSuffixWhiteList( policyResponse.whitelistedDomains() );

            //Prohibited wildcard
            tppPolicy.prohibitWildcard( policyResponse.wildcardsAllowed() ? 0 : 1);

            //Certificate authority
            tppPolicy.certificateAuthority( policyResponse.certificateAuthority() != null ? policyResponse.certificateAuthority().value() : null);

            //Subject
            SubjectResponse subjectResponse = policyResponse.subject();

            if( subjectResponse != null ) {
                //Organization
                if ( subjectResponse.organization() != null )
                    tppPolicy.organization( subjectResponse.organization().value(), subjectResponse.organization().locked());

                //Org Unit
                if ( subjectResponse.organizationalUnit() != null )
                    tppPolicy.organizationalUnit( subjectResponse.organizationalUnit().values(), subjectResponse.organizationalUnit().locked() );

                //City
                if ( subjectResponse.city() != null )
                    tppPolicy.city( subjectResponse.city().value(), subjectResponse.city().locked() );

                //State
                if ( subjectResponse.state() != null )
                    tppPolicy.state( subjectResponse.state().value(), subjectResponse.state().locked() );

                //country
                if ( subjectResponse.country() != null )
                    tppPolicy.country( subjectResponse.country().value(), subjectResponse.country().locked()  );
            }

            //KeyPair
            KeyPairResponse keyPairResponse = policyResponse.keyPair();

            if ( keyPairResponse != null ) {
                //KeyAlgorithm
                if( keyPairResponse.keyAlgorithm() != null )
                    tppPolicy.keyAlgorithm( keyPairResponse.keyAlgorithm().value(), keyPairResponse.keyAlgorithm().locked());

                //Key Bit Strength
                if( keyPairResponse.keySize() != null )
                    tppPolicy.keyBitStrength( keyPairResponse.keySize().value().toString(), keyPairResponse.keySize().locked() );


                //Elliptic Curve
                if( keyPairResponse.ellipticCurve() != null )
                    tppPolicy.ellipticCurve( keyPairResponse.ellipticCurve().value(), keyPairResponse.ellipticCurve().locked() );
            }

            //Manual Csr
            if( policyResponse.csrGeneration() != null)
                if( policyResponse.csrGeneration().value().equals("ServiceGenerated") )
                    tppPolicy.manualCsr("0", policyResponse.csrGeneration().locked());
                else
                    if( policyResponse.csrGeneration().value().equals("UserProvided") )
                        tppPolicy.manualCsr("1", policyResponse.csrGeneration().locked());

            //TODO Confirm with Angel if this attribute is lockeable or not
            //AllowPrivate Key Reuse
            tppPolicy.allowPrivateKeyReuse( policyResponse.privateKeyReuseAllowed() ? "1" : "0", true );

            //TODO Confirm with Angel if this attribute is lockeable or not
            //TppWantRenewal
            tppPolicy.wantRenewal( policyResponse.privateKeyReuseAllowed() ? "1" : "0", true );

            //Prohibited SAN Types
            setProhibitedSANTypes(tppPolicy, policyResponse);
        }

        return tppPolicy;
    }

    private void setProhibitedSANTypes( TPPPolicy tppPolicy, PolicyResponse policyResponse ) {

        List<String> prohibitedSANTypes = new ArrayList<>();

        if ( policyResponse.subjAltNameDnsAllowed() )
            prohibitedSANTypes.add(AltName.DNS.value);

        if ( policyResponse.subjAltNameIpAllowed() )
            prohibitedSANTypes.add(AltName.IP.value);

        if ( policyResponse.subjAltNameEmailAllowed() )
            prohibitedSANTypes.add(AltName.EMAIL.value);

        if ( policyResponse.subjAltNameUriAllowed() )
            prohibitedSANTypes.add(AltName.URI.value);

        if ( policyResponse.subjAltNameUpnAllowed() )
            prohibitedSANTypes.add(AltName.UPN.value);

        if( prohibitedSANTypes.size()>0 )
            tppPolicy.prohibitedSANTypes(prohibitedSANTypes.toArray(new String[0]));
    }

    @Data
    @AllArgsConstructor
    public static class AuthorizeRequest {
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class AuthorizeTokenRequest{

        @SerializedName("username")
        private String username;

        @SerializedName("password")
        private String password;

        @SerializedName("client_id")
        private String clientId;

        @SerializedName("scope")
        private String scope;

        @SerializedName("state")
        private String state;

        @SerializedName("redirect_uri")
        private String redirectUri;

    }

    @Data
    @AllArgsConstructor
    static class RefreshTokenRequest{
        @SerializedName("refresh_token")
        private String refreshToken;
        @SerializedName("client_id")
        private String clientId;
    }

    @Data
    @AllArgsConstructor
    public static class ReadZoneConfigurationRequest {
        String policyDN;
    }

    @Data
    public static class ReadZoneConfigurationResponse {
        Object error;
        ServerPolicy policy;
    }

    @Data
    public static class CertificateRequestsPayload {
        @SerializedName("PolicyDN")
        private String policyDN;
        @SerializedName("CADN")
        private String cadn;
        private String objectName;
        private String subject;
        private String organizationalUnit;
        private String organization;
        private String city;
        private String state;
        private String country;
        @SerializedName("SubjectAltNames")
        private Collection<SANItem> subjectAltNames;
        private String contact;
        @SerializedName("CASpecificAttributes")
        private Collection<NameValuePair<String, String>> caSpecificAttributes;
        @SerializedName("PKCS10")
        private String pkcs10;
        private String keyAlgorithm;
        private int keyBitSize;
        private String ellipticCurve;
        private boolean disableAutomaticRenewal;
        private String origin;
        
        @SerializedName("CustomFields")
        private ArrayList<CustomFieldRequest> customFields;
    }

    @Data
    protected static class SANItem {
        private int type;
        private String name;
    }

    @Data
    @AllArgsConstructor
    public static class NameValuePair<K, V> {
        private K name;
        private V value;
    }

    @Data
    public class CertificateRetrieveRequest {
        private String certificateDN;
        private String format;
        private String password;
        private boolean includePrivateKey;
        private boolean includeChain;
        private String friendlyName;
        private boolean rootFirstOrder;
    }

    @Data
    public class CertificateRevokeRequest {
        private String certificateDN;
        private String thumbprint;
        private Integer reason;
        private String comments;
        private boolean disable;
    }

    @Data
    public class CertificateRenewalRequest {
        private String certificateDN;
        private String PKCS10;
    }
}
