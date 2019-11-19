package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Data;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;

@Data
public class CertificateIssuingTemplate {

  public String id;
  public String companyId;
  public String certificateAuthority;
  public String name;
  public String certificateAuthorityAccountId;
  public String certificateAuthorityProductOptionId;
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
  public List<String> sanDnsNameRegexes;
  public List<String> sanIpAddressRegexes;
  public List<String> sanRfc822NameRegexes;
  public List<AllowedKeyType> keyTypes;
  public Boolean keyReuse;

  @Data
  @AllArgsConstructor
  public static class AllowedKeyType {
    private String keyType;
    private List<Integer> keyLengths;

  }

  public Policy toPolicy() {
    List<AllowedKeyConfiguration> allowedKeyConfigurations = keyTypes.stream()
        .map(kt -> new AllowedKeyConfiguration(KeyType.from(kt.keyType), kt.keyLengths, null))
        .collect(Collectors.toList());

    Policy policy = Policy.builder().subjectCNRegexes(subjectCNRegexes)
        .subjectCRegexes(subjectCValues).subjectLRegexes(subjectLRegexes)
        .subjectORegexes(subjectORegexes).subjectOURegexes(subjectOURegexes)
        .subjectSTRegexes(subjectSTRegexes).dnsSanRegExs(sanDnsNameRegexes)
        .ipSanRegExs(sanIpAddressRegexes).emailSanRegExs(sanRfc822NameRegexes)
        .allowedKeyConfigurations(allowedKeyConfigurations).allowKeyReuse(keyReuse).build();
    return policy;
  }

}
