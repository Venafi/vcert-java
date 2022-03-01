package com.venafi.vcert.sdk.policy.converter.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.features.SupportedKeyPairs;
import com.venafi.vcert.sdk.features.SupportedRSAKeySizes;
import com.venafi.vcert.sdk.policy.domain.*;
import com.venafi.vcert.sdk.policy.converter.IPolicySpecificationValidator;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class CloudPolicySpecificationValidator implements IPolicySpecificationValidator {

    public static final String CERTIFICATE_AUTHORITY_EXCEPTION_MESSAGE = "Certificate Authority is invalid, please provide a valid value with this structure: ca_type\\ca_account_key\\vendor_product_name";
    public static final String MAX_VALID_DAYS_EXCEPTION_MESSAGE = "The Max Valid days value should be an positive integer or zero( it will be converted to the default which is 365)";
    public static final String ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE = "The specified policy attribute %s has more than one value";
    public static final String ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE = "The specified policy attribute %s contains the \".*\" but contains another values.";
    public static final String ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE = "The specified policy attribute %s has a value which is not a two-char string value.";
    public static final String ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE = "The specified value for policy attribute %s doesn't match with the supported ones";
    public static final String DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE = "The specified value for default attribute %s doesn't match with the supported ones";
    public static final String DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE = "The specified value for default attribute %1$s doesn't match with the value of policy attribute %2$s";
    public static final String SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE = "The specified attribute %1$s can't be true due only DNS is supported.";

    public static final CloudPolicySpecificationValidator INSTANCE = new CloudPolicySpecificationValidator();

    private CloudPolicySpecificationValidator(){}

    @Override
    public void validate(PolicySpecification policySpecification) throws Exception {
        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null) {

            validateMaxValidDays( policy );

            validateCertificateAuthority( policy );

            validatePolicySubject( policy.subject() );

            validateKeyPair( policy.keyPair() );

            validateSubjectAltNames( policy.subjectAltNames() );
        }

        if(defaults != null) {
            validateDefaultSubject( defaults.subject(), policy!=null ? policy.subject() : null );

            validateDefaultKeyPair( defaults.keyPair(), policy!=null ? policy.keyPair() : null );
        }
    }

    private void validateCertificateAuthority( Policy policy ) throws VCertException {
        if ( policy.certificateAuthority()!=null && StringUtils.split(policy.certificateAuthority(), "\\").length < 3 )
            throw new VCertException(CERTIFICATE_AUTHORITY_EXCEPTION_MESSAGE);
    }

    private void validateMaxValidDays( Policy policy ) throws VCertException {
        if( policy.maxValidDays() != null && !(policy.maxValidDays() >= 0) )
            throw new VCertException(MAX_VALID_DAYS_EXCEPTION_MESSAGE);
    }

    private void validatePolicySubject(Subject subject) throws VCertException {

        if (subject != null) {
            if (subject.orgs() != null && subject.orgs().length > 1 && Arrays.stream(subject.orgs()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals))
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS));

            if (subject.orgUnits() != null && subject.orgUnits().length > 1 && Arrays.stream(subject.orgUnits()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals))
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS));

            if (subject.localities() != null && subject.localities().length > 1 && Arrays.stream(subject.localities()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals))
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES));

            if (subject.states() != null && subject.states().length > 1 && Arrays.stream(subject.states()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals))
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES));

            if (subject.countries() != null && subject.countries().length > 1 && Arrays.stream(subject.countries()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals))
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_CONTAINING_ALLOW_ALL_STRING_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));

            if (subject.countries() != null && subject.countries().length > 0)
                for (String country: subject.countries())
                    if( country.length() != 2 )
                        throw new VCertException(String.format(ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));
        }
    }

    private void validateKeyPair(KeyPair keyPair) throws VCertException {

        if(keyPair != null) {

            //validate algorithm
            if(keyPair.keyTypes() != null) {
                int keyTypesLength = keyPair.keyTypes().length;

                if (keyTypesLength > 0 && !SupportedKeyPairs.VAAS.containsKeyTypes(keyPair.keyTypes()))
                    throw new VCertException(String.format(ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES));
            }

            //validate key bit strength
            if(keyPair.rsaKeySizes() != null) {
                if (!SupportedRSAKeySizes.VAAS.containsRsaKeySizes(keyPair.rsaKeySizes()))
                    throw new VCertException(String.format(ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES));
            }
        }
    }

    private void validateSubjectAltNames(SubjectAltNames subjectAltNames) throws VCertException {
        if(subjectAltNames.ipAllowed() != null && subjectAltNames.ipAllowed())
            throw new VCertException(String.format(SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED));

        if(subjectAltNames.emailAllowed() != null && subjectAltNames.emailAllowed())
            throw new VCertException(String.format(SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED));

        if(subjectAltNames.uriAllowed() != null && subjectAltNames.uriAllowed())
            throw new VCertException(String.format(SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED));

        if(subjectAltNames.upnAllowed() != null && subjectAltNames.upnAllowed())
            throw new VCertException(String.format(SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_UPN_ALLOWED));
    }

    private void validateDefaultSubject(DefaultsSubject defaultsSubject, Subject policySubject) throws VCertException {

        if (defaultsSubject != null) {

            if (policySubject != null) {

                if( policySubject.orgs() != null && defaultsSubject.org() != null && !defaultsSubject.org().equals("")
                        && !Arrays.stream(policySubject.orgs()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals)
                        && !Arrays.stream(policySubject.orgs()).anyMatch(defaultsSubject.org()::equals)//!policySubject.orgs()[0].equals(defaultsSubject.org())
                )
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS));

                if( policySubject.orgUnits() != null && defaultsSubject.orgUnits() != null
                        && !Arrays.stream(policySubject.orgUnits()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals)
                        && !Arrays.asList(policySubject.orgUnits()).containsAll(Arrays.asList(defaultsSubject.orgUnits()))
                )
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS));

                if( policySubject.localities() != null  && defaultsSubject.locality() != null && !defaultsSubject.locality().equals("")
                        && !Arrays.stream(policySubject.localities()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals)
                        && !Arrays.stream(policySubject.localities()).anyMatch(defaultsSubject.locality()::equals)
                )
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY, PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES));

                if( policySubject.states() != null && defaultsSubject.state() != null && !defaultsSubject.state().equals("")
                        && !Arrays.stream(policySubject.states()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals)
                        && !Arrays.stream(policySubject.states()).anyMatch(defaultsSubject.state()::equals)
                )
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE, PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES));

                if( policySubject.countries() != null && defaultsSubject.country() != null && !defaultsSubject.country().equals("")
                        && !Arrays.stream(policySubject.countries()).anyMatch(PolicySpecificationConst.ALLOW_ALL::equals)
                        && !Arrays.stream(policySubject.countries()).anyMatch(defaultsSubject.country()::equals)
                )
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));
            }

            if ( defaultsSubject.country() != null && !(defaultsSubject.country().length() == 2) )
                throw new VCertException(String.format(ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY));
        }
    }

    private void validateDefaultKeyPair(DefaultsKeyPair defaultsKeyPair, KeyPair policyKeyPair) throws VCertException {

        if (defaultsKeyPair != null) {

            String defaultKeyType = defaultsKeyPair.keyType();
            if ( defaultKeyType != null && !defaultKeyType.equals("")) {
                if(!SupportedKeyPairs.VAAS.containsKeyType( defaultKeyType ))
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE));

                if(policyKeyPair != null) {
                    String[] policyKeyTypes = policyKeyPair.keyTypes();
                    if (policyKeyTypes != null && policyKeyTypes.length == 1 && !policyKeyTypes[0].equals("") && !policyKeyTypes[0].equals(defaultKeyType))
                        throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES));
                }
            }

            Integer defaultRsaKeySize = defaultsKeyPair.rsaKeySize();
            if( defaultRsaKeySize != null ) {
                if( !SupportedRSAKeySizes.VAAS.containsRsaKeySize( defaultRsaKeySize ))
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE));

                if(policyKeyPair != null && !Arrays.stream(policyKeyPair.rsaKeySizes()).anyMatch(defaultRsaKeySize::equals))
                    throw new VCertException(String.format(DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES));
            }
        }
    }

}