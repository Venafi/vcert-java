package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import lombok.Data;

@Data
public class DigicertCIT extends CertificateIssuingTemplate {

    @Override
    public Product product() {
        Product product = super.product();
        if ( product == null) {
            product = new DigicertProduct();
            product(product);
        }
        return product;
    }

    @Data
    public static class DigicertProduct extends Product {
        private String hashAlgorithm = "SHA256";
        private Boolean autoRenew = false;
        private Integer organizationId;
    }
}
