package com.venafi.vcert.sdk.policyspecification.api.domain;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

@Data
public class CloudPolicy {
    private CertificateIssuingTemplate certificateIssuingTemplate;
    private CAInfo caInfo;

    @Data
    @AllArgsConstructor
    public static class CAInfo {

        private String certificateAuthorityString;
        private String caType;
        private String caAccountKey;
        private String vendorProductName;

        public CAInfo(String certificateAuthority) {

            this.certificateAuthorityString = certificateAuthority;

            String[] caInfoArray = StringUtils.split(certificateAuthorityString, "\\");

            this.caType = caInfoArray[0];
            this.caAccountKey = caInfoArray[1];
            this.vendorProductName = caInfoArray[2];
        }

        public CAInfo(String caType, String caAccountKey, String vendorProductName) {
            this.caType = caType;
            this.caAccountKey = caAccountKey;
            this.vendorProductName = vendorProductName;

            certificateAuthorityString = caType+"\\"+caAccountKey+"\\"+vendorProductName;
        }
    }
}


