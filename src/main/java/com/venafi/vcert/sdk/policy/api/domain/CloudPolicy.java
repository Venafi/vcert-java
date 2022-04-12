package com.venafi.vcert.sdk.policy.api.domain;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

@Data
public class CloudPolicy {
    private CertificateIssuingTemplate certificateIssuingTemplate;
    private CAInfo caInfo;
    private String[] owners;
    
    //this attribute is not corresponding to any VaaS attribute. It only exists to indicate to the
    // CloudPolicyToPolicyConverter class that when the domains of the PolicySpecification which is 
    //being built then they should be cleaned up of regexes or not.
    private boolean removeRegexesFromSubjectCN;

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


