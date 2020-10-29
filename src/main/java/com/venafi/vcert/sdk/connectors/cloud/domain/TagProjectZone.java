package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.time.OffsetDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TagProjectZone {
  private String id;
  private String companyId;
  private String devopsProjectId;
  private String name;
  private String certificateIssuingTemplateId;
  private OffsetDateTime creationDate;
}
