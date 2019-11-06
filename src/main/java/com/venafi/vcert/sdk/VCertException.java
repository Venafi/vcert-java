package com.venafi.vcert.sdk;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import feign.FeignException;
import lombok.Data;

public class VCertException extends Exception {

  public VCertException() {
    super();
  }

  public VCertException(String message) {
    super(message);
  }

  public VCertException(Exception cause) {
    super(cause);
  }

  public VCertException(String message, Exception cause) {
    super(message, cause);
  }

  public static void throwIfNull(Object testee, String message) throws VCertException {
    if (testee != null) {
      return;
    }
    if (message != null) {
      throw new VCertException(message);
    }
    throw new VCertException();
  }

  public static VCertException fromFeignException(FeignException feignException) {
    Gson gson = new GsonBuilder().create();
    VenafiTppErrorResponse tppResponse =
        gson.fromJson(feignException.contentUTF8(), VenafiTppErrorResponse.class);
    if (Objects.nonNull(tppResponse) && tppResponse.error() != null) {
      return new VCertException(feignException.getMessage() + ": " + tppResponse.error(),
          feignException);
    }
    VenafiCloudErrorResponse response =
        gson.fromJson(feignException.contentUTF8(), VenafiCloudErrorResponse.class);
    if (Objects.nonNull(response) && response.errors() != null && !response.errors().isEmpty()) {
      return new VCertException(
          feignException.getMessage() + ": " + response.errors().stream()
              .map(VenafiServerError::message).collect(Collectors.joining(System.lineSeparator())),
          feignException);
    }
    return new VCertException(feignException);
  }

  @Data
  private static class VenafiCloudErrorResponse {
    private Collection<VenafiServerError> errors;
  }

  @Data
  private static class VenafiTppErrorResponse {
    @SerializedName("Error")
    private String error;
  }

  @Data
  private static class VenafiServerError {
    private int code;
    private String message;
    private Collection<String> args;
  }
}
