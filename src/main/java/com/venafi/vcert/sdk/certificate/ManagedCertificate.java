package com.venafi.vcert.sdk.certificate;

import lombok.Data;

@Data
public class ManagedCertificate {
    private String id;
    private String companyId;
    private String latestCertificateRequestId;
    private String certificateName;
}
