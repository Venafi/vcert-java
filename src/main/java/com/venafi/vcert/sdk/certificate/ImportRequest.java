package com.venafi.vcert.sdk.certificate;

import lombok.Data;

import java.util.Map;

@Data
public class ImportRequest {
    String policyDN;
    String objectName;
    String certificateData;
    String privateKeyData;
    String password;
    boolean reconcile;
    Map<String, String> cASpecificAttributes;
}
