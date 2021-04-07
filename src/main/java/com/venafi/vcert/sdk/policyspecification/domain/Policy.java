package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class Policy {

    private String[] domains;
    private Boolean wildcardAllowed;
    private Integer maxValidDays;
    private String certificateAuthority;
    private Subject subject;
    private KeyPair keyPair;
    private SubjectAltNames subjectAltNames;
}
