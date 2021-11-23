package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.time.OffsetDateTime;
import lombok.Data;

@Data
public class EdgeEncryptionKey {

  private String id;
  private String companyId;
  private String key;
  private String keyAlgorithm;
  private OffsetDateTime lastBackupDate;
}
