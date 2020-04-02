package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Project {

  private String id;
  private String companyId;
  private String name;
  private String description;
  private List<String> users;
  private List<ProjectZone> zones;
}
