package com.venafi.vcert.sdk.policyspecification.domain;

public interface PolicySpecificationConst {

    //
    String ALLOW_ALL = ".*";

    //POLICY SPECIFICATION ATTRIBUTES
    String ATT_NAME = "name";
    String ATT_OWNERS = "owners";
    String ATT_USERS = "users";
    String ATT_USER_ACCESS = "userAccess";
    String ATT_APPROVERS = "approvers";
    String ATT_POLICY = "policy";
    String ATT_DEFAULTS = "defaults";

    //POLICY ATTRIBUTES
    String ATT_POLICY_DOMAINS = "domains";
    String ATT_POLICY_WILDCARD_ALLOWED = "wildcardAllowed";
    String ATT_POLICY_MAX_VALID_DAYS = "maxValidDays";
    String ATT_POLICY_CERTIFICATE_AUTHORITY = "certificateAuthority";
    String ATT_POLICY_AUTO_INSTALLED = "autoInstalled";
    String ATT_POLICY_SUBJECT = "subject";
    String ATT_POLICY_KEYPAIR = "keyPair";
    String ATT_POLICY_SUBJECT_ALT_NAMES = "subjectAltNames";
    //POLICY SUBJECT ATTRIBUTES
    String ATT_POLICY_SUBJECT_ORGS = "orgs";
    String ATT_POLICY_SUBJECT_ORG_UNITS = "orgUnits";
    String ATT_POLICY_SUBJECT_LOCALITIES = "localities";
    String ATT_POLICY_SUBJECT_STATES = "states";
    String ATT_POLICY_SUBJECT_COUNTRIES = "countries";
    //POLICY KEYPAIR ATTRIBUTES
    String ATT_POLICY_KEYPAIR_KEY_TYPES = "keyTypes";
    String ATT_POLICY_KEYPAIR_RSA_KEY_SIZES = "rsaKeySizes";
    String ATT_POLICY_KEYPAIR_ELLIPTIC_CURVES = "ellipticCurves";
    //String ATT_POLICY_KEYPAIR_GENERATION_TYPE = "generationType";
    String ATT_POLICY_KEYPAIR_SERVICE_GENERATED_TYPE = "serviceGenerated";
    String ATT_POLICY_KEYPAIR_REUSE_ALLOWED = "reuseAllowed";
    //POLICY SUBJECT_ALT_NAMES ATTRIBUTES
    String ATT_POLICY_SUBJECT_ALT_NAMES_DNS_ALLOWED = "dnsAllowed";
    String ATT_POLICY_SUBJECT_ALT_NAMES_IP_ALLOWED = "ipAllowed";
    String ATT_POLICY_SUBJECT_ALT_NAMES_EMAIL_ALLOWED = "emailAllowed";
    String ATT_POLICY_SUBJECT_ALT_NAMES_URI_ALLOWED = "uriAllowed";
    String ATT_POLICY_SUBJECT_ALT_NAMES_UPN_ALLOWED = "upnAllowed";

    //DEFAULTS ATTRIBUTES
    String ATT_DEFAULTS_DOMAIN = "domain";
    String ATT_DEFAULTS_AUTO_INSTALLED = "autoInstalled";
    String ATT_DEFAULTS_SUBJECT = "subject";
    String ATT_DEFAULTS_KEYPAIR = "keyPair";
    //DEFAULTS SUBJECT ATTRIBUTES
    String ATT_DEFAULTS_SUBJECT_ORG = "org";
    String ATT_DEFAULTS_SUBJECT_ORG_UNITS = "orgUnits";
    String ATT_DEFAULTS_SUBJECT_LOCALITY = "locality";
    String ATT_DEFAULTS_SUBJECT_STATE = "state";
    String ATT_DEFAULTS_SUBJECT_COUNTRY = "country";
    //DEFAULT KEYPAIR ATTRIBUTES
    String ATT_DEFAULTS_KEYPAIR_KEY_TYPE = "keyType";
    String ATT_DEFAULTS_KEYPAIR_RSA_KEY_SIZE = "rsaKeySize";
    String ATT_DEFAULTS_KEYPAIR_ELLIPTIC_CURVE = "ellipticCurve";
    //String ATT_DEFAULTS_KEYPAIR_GENERATION_TYPE = "generationType";
    String ATT_DEFAULTS_KEYPAIR_SERVICE_GENERATED_TYPE = "serviceGenerated";
}
