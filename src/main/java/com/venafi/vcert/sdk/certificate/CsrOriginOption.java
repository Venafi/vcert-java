package com.venafi.vcert.sdk.certificate;

public enum CsrOriginOption {
  LocalGeneratedCSR,
  ServiceGeneratedCSR,
  UserProvidedCSR;

  public static CsrOriginOption defaultCsrOrigin() {
    return LocalGeneratedCSR;
  }
}
