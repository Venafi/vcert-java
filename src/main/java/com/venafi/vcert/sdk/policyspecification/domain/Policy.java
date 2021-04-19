package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Policy {

    private String[] domains;
    private Boolean wildcardAllowed;
    private Integer maxValidDays;
    private String certificateAuthority;
    private Boolean autoInstalled;
    private Subject subject;
    private KeyPair keyPair;
    private SubjectAltNames subjectAltNames;
}
