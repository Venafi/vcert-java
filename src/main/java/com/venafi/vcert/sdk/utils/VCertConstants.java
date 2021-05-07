package com.venafi.vcert.sdk.utils;

public class VCertConstants {
  public static final String DEFAULT_VENDOR_AND_PRODUCT_NAME = "Venafi VCert-Java";

  public static final String TPP_CA_NAME = System.getenv("TPP_CA_NAME");
  public static final String CLOUD_ENTRUST_CA_NAME = System.getenv("CLOUD_ENTRUST_CA_NAME");
  public static final String CLOUD_DIGICERT_CA_NAME = System.getenv("CLOUD_DIGICERT_CA_NAME");
  public static final String CLOUD_DEFAULT_CA = "BUILTIN\\Built-In CA\\Default Product";
  public static final String TPP_PM_ROOT = System.getenv("TPP_PM_ROOT");
}
