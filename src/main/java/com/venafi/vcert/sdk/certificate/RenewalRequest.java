package com.venafi.vcert.sdk.certificate;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RenewalRequest {
  private String certificateDN;
  private String thumbprint;
  private CertificateRequest request;
}
