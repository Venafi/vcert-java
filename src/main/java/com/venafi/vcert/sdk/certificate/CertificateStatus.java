package com.venafi.vcert.sdk.certificate;

import java.util.Collection;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class CertificateStatus {
  @SerializedName("Id")
  private String id;
  private String managedCertificateId;
  private String zoneId;
  private String status;
  private CertificateStatueErrorInfomation errorInformation;
  private String creationDate;
  private String modificationDate;
  private String certificateSigningRequest;
  private String subjectDN;

  @Data
  private static class CertificateStatueErrorInfomation {
    private String type;
    private Integer code;
    private String message;
    private Collection<String> args;
  }
}
