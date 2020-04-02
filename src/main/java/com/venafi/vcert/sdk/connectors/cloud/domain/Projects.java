package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.List;
import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Projects {

  @SerializedName("devopsProjects")
  private List<Project> projects;
}
