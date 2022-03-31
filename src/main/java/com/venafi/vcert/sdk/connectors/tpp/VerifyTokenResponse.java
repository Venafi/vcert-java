package com.venafi.vcert.sdk.connectors.tpp;

import java.time.OffsetDateTime;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class VerifyTokenResponse {

  private String identity;
  
  private String application;

  @SerializedName("access_issued_on")
  private OffsetDateTime accessIssuedOn;
  
  @SerializedName("expires")
  private OffsetDateTime expires;
  
  @SerializedName("grant_issued_on")
  private OffsetDateTime grantIssuedOn;
  
  private String scope;
  
}
