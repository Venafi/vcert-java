package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import lombok.Data;

import java.util.List;

@Data
public class CAAccount {

    private Account account;
    private List<ProductOption> productOptions;

    @Data
    public static class Account {
        private String id;
        private String certificateAuthority;
        private String key;
    }

    @Data
    public static class ProductOption {
        private String id;
        private String productName;
        private ProductDetails productDetails;
    }

    @Data
    public static class ProductDetails {
        private ProductTemplate productTemplate;
    }

    @Data
    public static class ProductTemplate {
        private Integer organizationId;
    }

}
