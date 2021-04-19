package com.venafi.vcert.sdk.connectors.tpp;

public interface TppPolicyConstants {

    String TPP_ROOT_PATH = "\\VED\\Policy\\";
    String POLICY_CLASS = "Policy";
    String POLICY_ATTRIBUTE_CLASS = "X509 Certificate";
    //tpp attributes
    String TPP_CONTACT = "Contact";
    String TPP_APPROVER = "Approver";
    String TPP_CERTIFICATE_AUTHORITY = "Certificate Authority";
    String TPP_MANAGEMENT_TYPE = "Management Type";
    String TPP_PROHIBIT_WILDCARD = "Prohibit Wildcard";
    String TPP_DOMAIN_SUFFIX_WHITELIST = "Domain Suffix Whitelist";
    String TPP_ORGANIZATION = "Organization";
    String TPP_ORGANIZATIONAL_UNIT = "Organizational Unit";
    String TPP_CITY = "City";
    String TPP_STATE = "State";
    String TPP_COUNTRY = "Country";
    String TPP_KEY_ALGORITHM = "Key Algorithm";
    String TPP_KEY_BIT_STRENGTH = "Key Bit Strength";
    String TPP_ELLIPTIC_CURVE = "Elliptic Curve";
    String TPP_MANUAL_CSR = "Manual Csr";
    String TPP_PROHIBITED_SAN_TYPES = "Prohibited SAN Types";
    String TPP_ALLOW_PRIVATE_KEY_REUSE = "Allow Private Key Reuse";
    String TPP_WANT_RENEWAL = "Want Renewal";
    String TPP_DNS_ALLOWED = "DNS";
    String TPP_IP_ALLOWED = "IP";
    String TPP_EMAIL_ALLOWED = "Email";
    String TPP_URI_ALLOWED = "URI";
    String TPP_UPN_ALLOWED = "UPN";
}
