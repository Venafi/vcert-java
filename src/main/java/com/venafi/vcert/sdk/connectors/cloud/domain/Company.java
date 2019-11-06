package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.time.OffsetDateTime;
import java.util.Collection;
import lombok.Data;

@Data
public class Company {
  private String id;
  private String name;
  private String companyType;
  private boolean active;
  private Collection<String> domains;
  private OffsetDateTime creationDate;
}
