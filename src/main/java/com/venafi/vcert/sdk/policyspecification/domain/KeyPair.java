package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class KeyPair {

    //private String keyType;
    private String[] keyTypes;
    //private String rsaKeySize;
    private Integer[] rsaKeySizes;
    //private String ellipticCurve;
    private String[] ellipticCurves;
    private Boolean serviceGenerated;
    private Boolean reuseAllowed;
}
