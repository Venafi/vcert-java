package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProjectZone {
  private String id;
  private String companyId;
  private String name;
  private OffsetDateTime creationDate;
  private CertificateIssuingTemplate cit;
}
