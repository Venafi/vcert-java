package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class Subject {

    //private String org;
    private String[] orgs;
    private String[] orgUnits;
    //private String locality;
    private String[] localities;
    //private String state;
    private String[] states;
    //private String country;
    private String[] countries;
}
