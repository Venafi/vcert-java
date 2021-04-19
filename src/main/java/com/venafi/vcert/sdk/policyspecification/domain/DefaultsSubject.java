package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DefaultsSubject {

    private String org;
    //private String[] orgs;
    private String[] orgUnits;
    private String locality;
    //private String[] localities;
    private String state;
    //private String[] states;
    private String country;
    //private String[] countries;
}
