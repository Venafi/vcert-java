package com.venafi.vcert.sdk.connectors;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import lombok.Data;
import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import com.venafi.vcert.sdk.utils.Is;

@Data
// TODO move up one package
public class ZoneConfiguration {

  private String organization;
  private List<String> organizationalUnit;
  private String country;
  private String province;
  private String locality;
  private Policy policy = new Policy(); // Go merges the policy struct into the ZoneConfiguration
                                        // one...
  private SignatureAlgorithm hashAlgorithm = SignatureAlgorithm.UnknownSignatureAlgorithm;

  private Map<String, String> customAttributeValues = new HashMap<>(); // Go SDK factory sets an
                                                                       // empty map

  private String zoneId;
  private AllowedKeyConfiguration keyConfig;
  private String applicationId;
  private String certificateIssuingTemplateId;

  /**
   * UpdateCertificateRequest updates a certificate request based on the zone configuration
   * retrieved from the remote endpoint
   * 
   * @return
   */
  public void applyCertificateRequestDefaultSettingsIfNeeded(CertificateRequest request) {
    CertificateRequest.PKIXName subject = request.subject();
    subject.organization(Entity.of(subject.organization(), organization).resolve());
    if (Is.blank(subject.organizationalUnit()) && !Is.blank(organizationalUnit)) {
      subject.organizationalUnit(organizationalUnit);
    }
    subject.country(Entity.of(subject.country(), country).resolve());
    subject.province(Entity.of(subject.province(), province).resolve());
    subject.locality(Entity.of(subject.locality(), locality).resolve());

    // apply defaults for settings that weren't specified and then make sure they comply with policy
    if (request.keyType() == null) {
      request
          .keyType(keyConfig != null && keyConfig.keyType() != null ? keyConfig.keyType() : KeyType.defaultKeyType());
    }

    switch (request.keyType()) {
      case ECDSA:
        if (request.keyCurve() == null) {
          request.keyCurve(EllipticCurve.ellipticCurveDefault());
        }
        if (request.signatureAlgorithm() == SignatureAlgorithm.UnknownSignatureAlgorithm) {
          request.signatureAlgorithm(SignatureAlgorithm.ECDSAWithSHA256);
        }
        break;

      default:
        if (request.keyLength() < KeyType.defaultRsaLength()) {
          request.keyLength(keyConfig != null && !Is.blank(keyConfig.keySizes())
              && keyConfig.keySizes().get(0) >= KeyType.defaultRsaLength() ? keyConfig.keySizes().get(0)
                  : KeyType.defaultRsaLength());
        }
        if (request.signatureAlgorithm() == SignatureAlgorithm.UnknownSignatureAlgorithm) {
          request.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);
        }
        break;
    }

    if (!Is.blank(policy.allowedKeyConfigurations())) {
      for (AllowedKeyConfiguration keyConf : policy.allowedKeyConfigurations()) {
        if (keyConf.keyType() == request.keyType()) {
          switch (request.keyType()) {
            case ECDSA: {
              if (!Is.blank(keyConf.keyCurves())) {
                if (!keyConf.keyCurves().contains(request.keyCurve())) {
                  request.keyCurve(keyConf.keyCurves().get(0));
                }
              }
              break;
            }
            case RSA: {
              if (!Is.blank(keyConf.keySizes())) {
                boolean sizeOK = false;
                for (Integer size : keyConf.keySizes()) {
                  if (size.equals(request.keyLength())) {
                    sizeOK = true;
                  }
                }
                if (!sizeOK) {
                  request.keyLength(keyConf.keySizes().get(0));
                }
              }
              break;
            }
          }
        }
      }
    }
  }

  private static class Entity {
    private List<String> target;
    private String source;

    private Entity() {

    }

    static Entity of(List<String> target, String source) {
      Entity entity = new Entity();
      entity.target = target;
      entity.source = (source != null)? source : "";
      return entity;
    }

    List<String> resolve() {
      //Adding  empty string validation. When Certificate Issuing Template uses .* as regex, it means any string is
      // valid, even empty or null strings
      return Is.blank(target)? Collections.singletonList(source) : target;
    }
  }

  public boolean validateCertificateRequest(CertificateRequest request) throws VCertException {
    if (!isComponentValid(policy.subjectCNRegexes(),
        Collections.singletonList(request.subject().commonName()), false)) {
      throw new VCertException(
          "The requested CN does not match any of the allowed CN regular expressions");
    }
    if (!isComponentValid(policy.subjectORegexes(), request.subject().organization(), false)) {
      throw new VCertException(
          "The requested Organization does not match any of the allowed Organization regular expressions");
    }
    if (!isComponentValid(policy.subjectOURegexes(), request.subject().organizationalUnit(), false)) {
      throw new VCertException(
          "The requested Organizational Unit does not match any of the allowed Organization Unit regular expressions");
    }
    if (!isComponentValid(policy.subjectSTRegexes(), request.subject().province(), false)) {
      throw new VCertException(
          "The requested State/Province does not match any of the allowed State/Province regular expressions");
    }
    if (!isComponentValid(policy.subjectLRegexes(), request.subject().locality(), false)) {
      throw new VCertException(
          "The requested Locality does not match any of the allowed Locality regular expressions");
    }
    if (!isComponentValid(policy.subjectCRegexes(), request.subject().country(), false)) {
      throw new VCertException(
          "The requested Country does not match any of the allowed Country regular expressions");
    }
    if (!isComponentValid(policy.dnsSanRegExs(), request.dnsNames(), true)) {
      throw new VCertException(
          "The requested Subject Alternative Name does not match any of the allowed Country regular expressions");
    }
    // todo (from Go SDK): add ip, email and over checking

    List<AllowedKeyConfiguration> allowedKeyConfigurations = policy.allowedKeyConfigurations();
    if (allowedKeyConfigurations != null && allowedKeyConfigurations.size() > 0) {
      for (AllowedKeyConfiguration keyConfiguration : allowedKeyConfigurations) {
        if (keyConfiguration.keyType() == request.keyType()) {
          if (request.keyLength() > 0) {
            for (Integer size : keyConfiguration.keySizes()) {
              if (size.equals(request.keyLength())) {
                return true;
              }
            }
          }
          return true;
        }
      }
      throw new VCertException(
          "The requested Key Type and Size do not match any of the allowed Key Types and Sizes");
    }

    return true;
  }

  private boolean isComponentValid(Collection<String> regexes, Collection<String> components, boolean optional) {
    if (regexes.isEmpty() || (optional && Is.blank(components))) {
      return true;
    }

    if (components != null) {
      for (String regex : regexes) {
        Pattern pattern;
        try {
          pattern = Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
          // TODO log error
          return false;
        }
        for (String component : components) {
          Matcher m = pattern.matcher(component);
          if (m.matches()) {
            return true; // todo: that seems wrong. Check if all policy rules need to be matched, or
                         // any one? (E.g.: Policy says location is [0]:Madrid,[1]:London - does it
                         // need to match either or both?) Also, if we have locations 0:London, 1:
                         // Brussels, 2: Madrid, won't this pass? Should it?
          }
        }
      }
    }
    return false;
  }
}


