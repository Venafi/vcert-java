package com.venafi.vcert.sdk;

public enum SignatureAlgorithm {

    MD2withRSA("MD2withRSA");

    /**
     *
     * @param standardName
     * @see <a href="https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#signature-algorithms">Standard Signature Algorithm Names</a>
     */
    SignatureAlgorithm(String standardName) {
        this.standardName = standardName;
    }

    private String standardName;
}
