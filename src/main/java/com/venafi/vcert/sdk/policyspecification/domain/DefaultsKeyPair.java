package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class DefaultsKeyPair {

    private String keyType;
    //private String[] keyTypes;
    private Integer rsaKeySize;
    //private String[] rsaKeySizes;
    private String ellipticCurve;
    //private String[] ellipticCurves;
    private Boolean serviceGenerated;
    //private boolean reuseAllowed;
}
