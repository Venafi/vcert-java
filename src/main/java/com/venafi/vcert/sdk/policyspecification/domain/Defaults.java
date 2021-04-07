package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class Defaults {

    private String domain;
    private DefaultsSubject subject;
    private DefaultsKeyPair keyPair;
}
