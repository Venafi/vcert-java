package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import lombok.Data;

@Data
public class EntrustCIT extends CertificateIssuingTemplate {

    private TrackingData trackingData;

    @Data
    public static class TrackingData {
        private String certificateAuthority = "ENTRUST";
        private String requesterName = "Venafi Cloud Service";
        private String requesterEmail = "no-reply@venafi.cloud";
        private String requesterPhone = "801-555-0123";
    }

}
