package com.venafi.vcert.sdk.certificate;

import lombok.Data;

@Data
public class ImportResponse {
    private String certificateDN;
    private int certificateVaultId;
    private String guid;
    private int privateKeyVaultId;
}
