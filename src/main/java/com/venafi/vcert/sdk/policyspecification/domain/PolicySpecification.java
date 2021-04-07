package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class PolicySpecification {

    private String name;
    private String[] owners;
    private String[] users;
    private String userAccess;
    private String[] approvers;

    private Policy policy;
    private Defaults defaults;

}
