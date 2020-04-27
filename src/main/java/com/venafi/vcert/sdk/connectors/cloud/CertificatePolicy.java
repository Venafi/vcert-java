package com.venafi.vcert.sdk.connectors.cloud;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import com.venafi.vcert.sdk.utils.Is;

@Data
public class CertificatePolicy {

  private String certificatePolicyType;
  private String id;
  private String companyId;
  private String name;
  // @SerializedName("systemGeneratedate") // todo: Go SDK uses this spelling, but server returns
  // the one below
  private String systemGenerated;
  private OffsetDateTime creationDate;
  private String certificateProviderId;
  private Collection<String> subjectCNRegexes;
  private List<String> subjectORegexes;
  private Collection<String> subjectOURegexes;
  private List<String> subjectSTRegexes;
  private List<String> subjectLRegexes;
  @SerializedName("subjectCValues")
  private List<String> subjectCRegexes;
  private Collection<String> sanRegexes;
  private Collection<AllowedKeyType> keyTypes;
  private boolean keyReuse;

  private static transient final Pattern nonRegEx = Pattern.compile("[a-zA-Z0-9 ]+");

  Policy toPolicy() {
    Function<Collection<String>, Collection<String>> addStartEndToCollection = cs -> {
      if (cs == null) {
        return Collections.emptyList();
      }
      return cs.stream().map(ServerPolicy.addStartEnd).collect(Collectors.toList());
    };
    Policy policy = new Policy().allowedKeyConfigurations(new ArrayList<>())
        .subjectCNRegexes(addStartEndToCollection.apply(subjectCNRegexes))
        .subjectOURegexes(addStartEndToCollection.apply(subjectOURegexes))
        .subjectCRegexes(addStartEndToCollection.apply(subjectCRegexes))
        .subjectSTRegexes(addStartEndToCollection.apply(subjectSTRegexes))
        .subjectLRegexes(addStartEndToCollection.apply(subjectLRegexes))
        .subjectORegexes(addStartEndToCollection.apply(subjectORegexes))
        .dnsSanRegExs(addStartEndToCollection.apply(sanRegexes)).allowKeyReuse(keyReuse);
    boolean allowWildcards = false;
    for (String s : policy.subjectCNRegexes()) {
      if (s.startsWith("^.*")) {
        allowWildcards = true;
      }
    }
    if (!allowWildcards) {
      for (String s : policy.dnsSanRegExs()) {
        if (s.startsWith("^.*")) {
          allowWildcards = true;
        }
      }
    }
    policy.allowWildcards(allowWildcards);
    if (keyTypes != null) {
      for (AllowedKeyType keyType : keyTypes) {
        AllowedKeyConfiguration keyConfiguration = new AllowedKeyConfiguration();
        // error checking; throws exception (i.e. panics) if invalid keyType
        keyConfiguration.keyType(KeyType.from(keyType.keyType()));
        keyConfiguration.keySizes(keyType.keyLengths != null ? new ArrayList<>(keyType.keyLengths)
            : Collections.emptyList());
        policy.allowedKeyConfigurations().add(keyConfiguration);
      }
    }
    return policy;
  }

  void toZoneConfig(ZoneConfiguration zoneConfig) { // todo: rename to augmentZoneConfig or
                                                    // addToZoneConfig ?
    if (!Is.blank(subjectCRegexes) && isNotRegexp(subjectCRegexes.get(0))) {
      zoneConfig.country(subjectCRegexes.get(0));
    }
    if (!Is.blank(subjectORegexes) && isNotRegexp(subjectORegexes.get(0))) {
      zoneConfig.organization(subjectORegexes.get(0));
    }
    if (!Is.blank(subjectSTRegexes) && isNotRegexp(subjectSTRegexes.get(0))) {
      zoneConfig.province(subjectSTRegexes.get(0));
    }
    if (!Is.blank(subjectLRegexes) && isNotRegexp(subjectLRegexes.get(0))) {
      zoneConfig.locality(subjectLRegexes.get(0));
    }
    if (null != subjectOURegexes) {
      for (String ou : subjectOURegexes) {
        if (isNotRegexp(ou)) {
          if (zoneConfig.organizationalUnit() == null) {
            zoneConfig.organizationalUnit(new ArrayList<>());
          }
          zoneConfig.organizationalUnit().add(ou);
        }
      }
    }
  }

  private boolean isNotRegexp(String s) {
    return nonRegEx.matcher(s).matches();
  }

  @Data
  private static class AllowedKeyType {
    private String keyType;
    private Collection<Integer> keyLengths;

  }
}
