package com.venafi.vcert.sdk.policy.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Defaults {

    private String domain;
    //private Boolean autoInstalled;
    private DefaultsSubject subject;
    private DefaultsKeyPair keyPair;
}
