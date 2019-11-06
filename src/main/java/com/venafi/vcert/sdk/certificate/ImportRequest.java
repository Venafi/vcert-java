package com.venafi.vcert.sdk.certificate;

import java.util.Map;
import lombok.Data;

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
