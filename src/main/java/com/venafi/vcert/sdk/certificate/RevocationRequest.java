package com.venafi.vcert.sdk.certificate;

import lombok.Data;

import java.util.Objects;

@Data
public class RevocationRequest {
    private String certificateDN;
    private String thumbprint;
    private String reason;
    private String comments;
    private boolean disable;

    public String reason(){
        return Objects.nonNull(reason)? reason : "";
    }
}
