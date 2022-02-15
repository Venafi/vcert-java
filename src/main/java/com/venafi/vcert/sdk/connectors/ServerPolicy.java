package com.venafi.vcert.sdk.connectors;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import com.google.common.annotations.VisibleForTesting;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import com.venafi.vcert.sdk.utils.Is;

@Data
@NoArgsConstructor // for testing
@AllArgsConstructor
public class ServerPolicy {

  private static transient final String allAllowedRegex = ".*";
  public static transient final Function<String, String> addStartEnd = s -> {
    if (!s.startsWith("^")) {
      s = "^" + s;
    }
    if (!s.endsWith("$")) {
      s += "$";
    }
    return s;
  };

  private LockableValue<String> certificateAuthority;
  private LockableValue<String> csrGeneration;
  private LockableValue<String> keyGeneration;
  private KeyPair keyPair;
  private LockableValue<String> managementType;

  private boolean privateKeyReuseAllowed;
  private boolean subjAltNameDnsAllowed;
  private boolean subjAltNameEmailAllowed;
  private boolean subjAltNameIpAllowed;
  private boolean subjAltNameUpnAllowed;
  private boolean subjAltNameUriAllowed;
  private Subject subject;
  private boolean uniqueSubjectEnforced;
  private Collection<String> whitelistedDomains;
  private boolean wildcardsAllowed;

  public Policy toPolicy() {
    Function<String, String> escapeOne = s -> addStartEnd.apply(Pattern.quote(s));
    Function<Collection<String>, Collection<String>> escapeCollection =
        in -> in.stream().map(escapeOne).collect(Collectors.toList());
    Function<LockableValue<String>, Collection<String>> selectValue = in -> {
      if (null == in) {
        return Collections.singleton(allAllowedRegex); // Go would provide empty structs with
                                                       // default values, so in Java, we have to
                                                       // deal with null instead
      }
      return in.locked() ? Collections.singleton(escapeOne.apply(in.value()))
          : Collections.singleton(allAllowedRegex);
    };
    Function<Boolean, Collection<String>> allOrNothing =
        bool -> bool ? Collections.singleton(allAllowedRegex) : Collections.emptyList();

    Policy policy = new Policy().allowedKeyConfigurations(new ArrayList<>());
    if (Is.blank(whitelistedDomains)) {
      policy.subjectCNRegexes(Collections.singleton(allAllowedRegex));
    } else {
      ArrayList<String> subjectCNRegexes = new ArrayList<>(whitelistedDomains.size());
      for (String whitelistedDomain : whitelistedDomains()) {
        if (wildcardsAllowed()) {
          subjectCNRegexes
              .add(addStartEnd.apply(allAllowedRegex + Pattern.quote("." + whitelistedDomain)));
        } else {
          subjectCNRegexes.add(escapeOne.apply(whitelistedDomain));
        }
      }
      policy.subjectCNRegexes(subjectCNRegexes);

    }
    if (this.subject.organizationalUnit().locked()) {
      policy.subjectOURegexes(escapeCollection.apply(this.subject.organizationalUnit().values()));
    } else {
      policy.subjectOURegexes(Collections.singleton(allAllowedRegex));
    }

    policy.subjectORegexes(selectValue.apply(subject.organization()));
    policy.subjectLRegexes(selectValue.apply(subject.city()));
    policy.subjectSTRegexes(selectValue.apply(subject.state()));
    policy.subjectCRegexes(selectValue.apply(subject.country()));

    if (subjAltNameDnsAllowed) {
      if (Is.blank(whitelistedDomains)) {
        policy.dnsSanRegExs(Collections.singleton(allAllowedRegex));
      } else {
        List<String> regExs = new ArrayList<>(whitelistedDomains.size());
        for (String whitelistedDomain : whitelistedDomains) {
          if (wildcardsAllowed) {
            regExs.add(addStartEnd.apply(allAllowedRegex + Pattern.quote("." + whitelistedDomain)));
          } else {
            regExs.add(escapeOne.apply(whitelistedDomain));
          }
        }
        policy.dnsSanRegExs(regExs);
      }
    } else {
      policy.dnsSanRegExs(Collections.emptyList());
    }

    policy.ipSanRegExs(allOrNothing.apply(subjAltNameIpAllowed));
    policy.emailSanRegExs(allOrNothing.apply(subjAltNameEmailAllowed));
    policy.uriSanRegExs(allOrNothing.apply(subjAltNameUriAllowed));
    policy.upnSanRegExs(allOrNothing.apply(subjAltNameUpnAllowed));

    if (keyPair.keyAlgorithm().locked()) {
      KeyType keyType = KeyType.from(keyPair.keyAlgorithm().value());
      AllowedKeyConfiguration key =
          new AllowedKeyConfiguration().keyType(keyType).keySizes(new ArrayList<Integer>()).keyCurves(new ArrayList<EllipticCurve>());
      if (KeyType.RSA.equals(keyType)) {
        if (keyPair.keySize().locked()) {
          for (Integer keySize : KeyType.allSupportedKeySizes()) {
            if (keySize >= keyPair.keySize().value() || keyPair.keySize().value() == null) {
              key.keySizes().add(keySize);
            }
          }
        } else {
          key.keySizes(KeyType.allSupportedKeySizes());
        }
      } else {
        if (keyPair.ellipticCurve().locked()) {
          EllipticCurve curve = EllipticCurve.from(keyPair.ellipticCurve().value());
          key.keyCurves().add(curve);
        } else {
          key.keyCurves(EllipticCurve.allSupportedCures());
        }
      }
      policy.allowedKeyConfigurations().add(key);
    } else {
      policy.allowedKeyConfigurations().add(new AllowedKeyConfiguration().keyType(KeyType.RSA)
          .keySizes(KeyType.allSupportedKeySizes()));
      policy.allowedKeyConfigurations().add(new AllowedKeyConfiguration().keyType(KeyType.ECDSA)
          .keyCurves(EllipticCurve.allSupportedCures()));
    }
    policy.allowWildcards(wildcardsAllowed);
    policy.allowKeyReuse(privateKeyReuseAllowed);
    return policy;
  }

  public ZoneConfiguration toZoneConfig() {
    return new ZoneConfiguration().customAttributeValues(new HashMap<>())
        .hashAlgorithm(SignatureAlgorithm.SHA256WithRSA).country(subject.country().value())
        .organization(subject.organization().value())
        .organizationalUnit(subject.organizationalUnit().values()).province(subject.state().value())
        .locality(subject.city().value());
  }

  @Data
  @AllArgsConstructor
  @VisibleForTesting
  public static class KeyPair {
    private LockableValue<String> keyAlgorithm;
    private LockableValue<Integer> keySize;
    private LockableValue<String> ellipticCurve;
  }

  @Data
  @NoArgsConstructor // for testing
  @AllArgsConstructor
  @VisibleForTesting
  public static class Subject {
    private LockableValue<String> city;
    private LockableValue<String> country;
    private LockableValue<String> organization;
    private LockableValues<String> organizationalUnit;
    private LockableValue<String> state;
  }

}
