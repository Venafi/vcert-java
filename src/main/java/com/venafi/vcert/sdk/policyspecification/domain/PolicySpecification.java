package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PolicySpecification {

    private String name;
    private String[] owners;
    private String[] users;
    private String userAccess;
    private String[] approvers;

    private Policy policy;
    private Defaults defaults;

}
