package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.time.OffsetDateTime;
import java.util.Collection;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class ApiKey {

  private String username;
  private String apiVersion;
  private String apiKeyStatus;
  private OffsetDateTime creationDate;
  private OffsetDateTime validityStartDate;
  private OffsetDateTime validityEndDate;

  @SerializedName("apitypes")
  private Collection<String> apiTypes;

  // present in JSON but not in Go SDK
  // private String userId;
  // private String companyId;
}
