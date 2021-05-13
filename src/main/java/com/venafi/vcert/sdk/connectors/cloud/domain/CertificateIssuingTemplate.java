package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import lombok.NoArgsConstructor;

@Data
public class CertificateIssuingTemplate {

  public String id;
  public String companyId;
  public String certificateAuthority;
  public String name;
  public String certificateAuthorityAccountId;
  public String certificateAuthorityProductOptionId;
  public Product product;
  public TrackingData trackingData;
  public Integer priority; // rank/priority within a CA
  public Boolean systemGenerated;
  public Date creationDate;
  public Date modificationDate;
  public String reason;
  public List<String> subjectCNRegexes;
  public List<String> subjectORegexes;
  public List<String> subjectOURegexes;
  public List<String> subjectSTRegexes;
  public List<String> subjectLRegexes;
  public List<String> subjectCValues;
  @SerializedName("sanRegexes")
  public List<String> sanDnsNameRegexes;
  public List<AllowedKeyType> keyTypes;
  public Boolean keyReuse;
  public RecommendedSettings recommendedSettings;
  //added due the response return it in this position.
  //For the case of the request to create/update it, this attribute is in the Product class level
  private String validityPeriod;

  @Data
  @AllArgsConstructor
  public static class Product {
    private String certificateAuthority;
    private String productName;
    private String validityPeriod;
    private String hashAlgorithm;
    private Boolean autoRenew;
    private Integer organizationId;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class TrackingData {
    private String certificateAuthority;
    private String requesterName;
    private String requesterEmail;
    private String requesterPhone;
  }

  @Data
  @AllArgsConstructor
  public static class AllowedKeyType {
    private String keyType;
    private List<Integer> keyLengths;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class RecommendedSettings {
    private String subjectOValue;
    private String subjectOUValue;
    private String subjectSTValue;
    private String subjectLValue;
    private String subjectCValue;
    private RecommendedSettingsKey key;
    private Boolean keyReuse;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class RecommendedSettingsKey {
    private String type;
    private Integer length;
  }

  public Policy toPolicy() {
    List<AllowedKeyConfiguration> allowedKeyConfigurations = keyTypes.stream()
        .map(kt -> new AllowedKeyConfiguration(KeyType.from(kt.keyType), kt.keyLengths, null))
        .collect(Collectors.toList());

    Policy policy = Policy.builder().subjectCNRegexes(subjectCNRegexes)
        .subjectCRegexes(subjectCValues).subjectLRegexes(subjectLRegexes)
        .subjectORegexes(subjectORegexes).subjectOURegexes(subjectOURegexes)
        .subjectSTRegexes(subjectSTRegexes).dnsSanRegExs(sanDnsNameRegexes)
        .allowedKeyConfigurations(allowedKeyConfigurations).allowKeyReuse(keyReuse).build();
    return policy;
  }

  public ZoneConfiguration toZoneConfig() {
    ZoneConfiguration zoneConfig = new ZoneConfiguration().customAttributeValues(new HashMap<>());
    if (recommendedSettings != null) {
      zoneConfig.country(recommendedSettings.subjectCValue).organization(recommendedSettings.subjectOValue)
          .organizationalUnit(Collections.singletonList(recommendedSettings.subjectOUValue))
          .province(recommendedSettings.subjectSTValue).locality(recommendedSettings.subjectLValue);
      if (recommendedSettings.key() != null) {

        String type = recommendedSettings.key().type != null ? recommendedSettings.key().type : KeyType.defaultKeyType().name();
        Integer length = recommendedSettings.key().length != null ? recommendedSettings.key().length : KeyType.defaultRsaLength();

        zoneConfig.keyConfig(new AllowedKeyConfiguration(KeyType.from(type),
            Collections.singletonList(length), null));

      }
    }
    return zoneConfig;
  }
}
