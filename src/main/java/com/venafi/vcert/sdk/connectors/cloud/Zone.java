package com.venafi.vcert.sdk.connectors.cloud;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.HashMap;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;

@Data
@SuppressWarnings("WeakerAccess")
public class Zone {
  private String id;
  private String companyId;
  private String tag;
  private String zoneType;
  private CertificatePolicyId certificatePolicyIds;
  @SerializedName("defaultCertificateIdentityPolicyId")
  private String defaultCertificateIdentityPolicy;
  @SerializedName("defaultCertificateUsePolicyId")
  private String defaultCertificateUsePolicy;
  private boolean systemGenerated; // TODO: Go SDK has this as bool systemGeneratedate, but server
                                   // returns our spelling
  private OffsetDateTime creationDate;

  ZoneConfiguration getZoneConfiguration(UserDetails user, CertificatePolicy policy) {
    ZoneConfiguration zoneConfig = new ZoneConfiguration().customAttributeValues(new HashMap<>());
    if (policy == null) {
      return zoneConfig;
    }
    zoneConfig.policy(policy.toPolicy());
    policy.toZoneConfig(zoneConfig);
    return zoneConfig;
  }

  @Data
  private static class CertificatePolicyId {
    @SerializedName("CERTIFICATE_IDENTITY")
    Collection<String> certificateIdentity;
    @SerializedName("CERTIFICATE_USE")
    Collection<String> certificateUse;
  }
}
