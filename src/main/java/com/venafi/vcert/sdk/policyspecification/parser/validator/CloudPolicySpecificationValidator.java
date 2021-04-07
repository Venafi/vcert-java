package com.venafi.vcert.sdk.policyspecification.parser.validator;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.policyspecification.domain.*;

import java.util.Arrays;

public class CloudPolicySpecificationValidator implements IPolicySpecificationValidator {

    private static final String ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE = "The specified policy attribute %s has more than one value";
    private static final String ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE = "The specified policy attribute %s has not a two-char string value.";
    private static final String SPECIFIED_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE = "The specified value for policy attribute %s doesn't match with the supported ones";
    private static final String SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE = "The specified value for default attribute %s doesn't match with the supported ones";
    private static final String SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE = "The specified value for default attribute %1$s doesn't match with the value of policy attribute %2$s";
    private static final String SPECIFIED_SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE = "The specified attribute %1$s can't be true due only DNS is supported.";


    public static final CloudPolicySpecificationValidator INSTANCE = new CloudPolicySpecificationValidator();

    private CloudPolicySpecificationValidator(){}

    @Override
    public void validate(PolicySpecification policySpecification) throws Exception {
        Policy policy = policySpecification.policy();
        Defaults defaults = policySpecification.defaults();

        if(policy != null) {
            validatePolicySubject( policy.subject() );

            validateKeyPair( policy.keyPair() );

            validateSubjectAltNames( policy.subjectAltNames() );
        }

        if(defaults != null) {
            validateDefaultSubject( defaults.subject(), policy!=null ? policy.subject() : null );

            validateDefaultKeyPair( defaults.keyPair(), policy!=null ? policy.keyPair() : null );
        }
    }

    private void validatePolicySubject(Subject subject) throws VCertException {

        if (subject != null) {

            if (subject.orgs() != null && subject.orgs().length > 1)
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS));

            if (subject.localities() != null && subject.localities().length > 1)
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES));

            if (subject.states() != null && subject.states().length > 1)
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES));

            if (subject.countries() != null && subject.countries().length > 1)
                throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));

            if (subject.countries() != null && subject.countries().length == 1 && !(subject.countries()[0].length() == 2))
                throw new VCertException(String.format(ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));
        }
    }

    private void validateKeyPair(KeyPair keyPair) throws VCertException {

        if(keyPair != null) {

            //validate algorithm
            if(keyPair.keyTypes() != null) {
                int keyTypesLength = keyPair.keyTypes().length;
                if (keyTypesLength > 1)
                    throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES));

                if (keyTypesLength == 1 && !CloudKeyPairEnums.containsKeyTypes(keyPair.keyTypes()))
                    throw new VCertException(String.format(SPECIFIED_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES));
            }

            //validate key bit strength
            if(keyPair.rsaKeySizes() != null) {
                int rsaKeySizesLength = keyPair.rsaKeySizes().length;
                if (rsaKeySizesLength > 1)
                    throw new VCertException(String.format(ATTRIBUTE_HAS_MORE_THAN_ONE_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES));

                if (rsaKeySizesLength == 1 && !CloudKeyPairEnums.containsRsaKeySizes(keyPair.rsaKeySizes()))
                    throw new VCertException(String.format(SPECIFIED_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES));
            }
        }
    }

    private void validateSubjectAltNames(SubjectAltNames subjectAltNames) throws VCertException {
        if(subjectAltNames.ipAllowed() != null && subjectAltNames.ipAllowed())
            throw new VCertException(String.format(SPECIFIED_SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED));

        if(subjectAltNames.emailAllowed() != null && subjectAltNames.emailAllowed())
            throw new VCertException(String.format(SPECIFIED_SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED));

        if(subjectAltNames.uriAllowed() != null && subjectAltNames.uriAllowed())
            throw new VCertException(String.format(SPECIFIED_SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED));

        if(subjectAltNames.upnAllowed() != null && subjectAltNames.upnAllowed())
            throw new VCertException(String.format(SPECIFIED_SUBJECT_ALT_NAME_ATTRIBUTE_DOESNT_SUPPORTED_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_POLICY_SUBJECT_ALT_NAMES_UPN_ALLOWED));
    }

    private void validateDefaultSubject(DefaultsSubject defaultsSubject, Subject policySubject) throws VCertException {

        if (defaultsSubject != null) {

            if (policySubject != null) {
                if( (policySubject.orgs() != null && policySubject.orgs().length == 1 && !policySubject.orgs()[0].equals("") )
                        && (defaultsSubject.org() != null && !defaultsSubject.org().equals("") )
                        && !policySubject.orgs()[0].equals(defaultsSubject.org())
                )
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORGS));

                if( policySubject.orgUnits() != null && defaultsSubject.orgUnits() != null && !Arrays.asList(policySubject.orgUnits()).containsAll(Arrays.asList(defaultsSubject.orgUnits())))
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_ORG_UNITS, PolicySpecificationConst.ATT_POLICY_SUBJECT_ORG_UNITS));

                if( (policySubject.localities() != null && policySubject.localities().length == 1 && !policySubject.localities()[0].equals("") )
                        && (defaultsSubject.locality() != null && !defaultsSubject.locality().equals("") )
                        && !policySubject.localities()[0].equals(defaultsSubject.locality())
                )
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_LOCALITY, PolicySpecificationConst.ATT_POLICY_SUBJECT_LOCALITIES));

                if( (policySubject.states() != null && policySubject.states().length == 1 && !policySubject.states()[0].equals("") )
                        && (defaultsSubject.state() != null && !defaultsSubject.state().equals("") )
                        && !policySubject.states()[0].equals(defaultsSubject.state())
                )
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_STATE, PolicySpecificationConst.ATT_POLICY_SUBJECT_STATES));

                if( (policySubject.countries() != null && policySubject.countries().length == 1 && !policySubject.countries()[0].equals("") )
                        && (defaultsSubject.country() != null && !defaultsSubject.country().equals("") )
                        && !policySubject.countries()[0].equals(defaultsSubject.country())
                )
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY, PolicySpecificationConst.ATT_POLICY_SUBJECT_COUNTRIES));
            }

            if ( defaultsSubject.country() != null && !(defaultsSubject.country().length() == 2) )
                throw new VCertException(String.format(ATTRIBUTE_HAS_NOT_A_TWO_CHAR_STRING_VALUE_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_SUBJECT_COUNTRY));
        }
    }

    private void validateDefaultKeyPair(DefaultsKeyPair defaultsKeyPair, KeyPair policyKeyPair) throws VCertException {

        if (defaultsKeyPair != null) {

            String defaultKeyType = defaultsKeyPair.keyType();
            if ( defaultKeyType != null && !defaultKeyType.equals("")) {
                if(!CloudKeyPairEnums.containsKeyType( defaultKeyType ))
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE));

                if(policyKeyPair != null) {
                    String[] policyKeyTypes = policyKeyPair.keyTypes();
                    if (policyKeyTypes != null && policyKeyTypes.length == 1 && !policyKeyTypes[0].equals("") && !policyKeyTypes[0].equals(defaultKeyType))
                        throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_KEY_TYPE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_KEY_TYPES));
                }
            }

            Integer defaultRsaKeySize = defaultsKeyPair.rsaKeySize();
            if( defaultRsaKeySize != null ) {
                if( !CloudKeyPairEnums.containsRsaKeySize( defaultRsaKeySize ))
                    throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_WITH_ACCEPTED_VALUES_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE));

                if(policyKeyPair != null) {
                    Integer[] policyRsaKeySizes = policyKeyPair.rsaKeySizes();
                    if (policyRsaKeySizes != null && policyRsaKeySizes.length == 1 && !policyRsaKeySizes[0].equals(defaultRsaKeySize))
                        throw new VCertException(String.format(SPECIFIED_DEFAULT_ATTRIBUTE_DOESNT_MATCH_EXCEPTION_MESSAGE, PolicySpecificationConst.ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE, PolicySpecificationConst.ATT_POLICY_KEYPAIR_RSA_KEY_SIZES));
                }
            }
        }
    }

}