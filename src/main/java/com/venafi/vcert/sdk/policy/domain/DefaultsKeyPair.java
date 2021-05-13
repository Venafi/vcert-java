package com.venafi.vcert.sdk.policy.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
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
