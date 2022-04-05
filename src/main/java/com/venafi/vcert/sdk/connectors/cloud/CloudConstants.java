package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;

public interface CloudConstants {
    String DIGICERT_TYPE = "DIGICERT";
    String ENTRUST_TYPE = "ENTRUST";
    CertificateIssuingTemplate.TrackingData ENTRUST_DEFAULT_TRACKING_DATA = new CertificateIssuingTemplate.TrackingData("ENTRUST", "Venafi Cloud Service", "no-reply@venafi.cloud", "801-555-0123");
    String OWNER_TYPE_USER = "USER";
    String OWNER_TYPE_TEAM = "TEAM";
}
