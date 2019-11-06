package com.venafi.vcert.sdk.connectors.tpp;

import java.time.OffsetDateTime;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
@SuppressWarnings("WeakerAccess")
public class AuthorizeResponse {

  @SerializedName("APIKey")
  private String apiKey;

  private OffsetDateTime validUntil;
}
