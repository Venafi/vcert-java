package com.venafi.vcert.sdk;

import lombok.Getter;

public enum SignatureAlgorithm {

    UnknownSignatureAlgorithm(""),
    MD2withRSA("MD2withRSA"),
    MD5WithRSA("MD5withRSA"),
    SHA1WithRSA("SHA1withRSA"),
    SHA256WithRSA("SHA256withRSA"),
    SHA384WithRSA("SHA384withRSA"),
    SHA512WithRSA("SHA512withRSA"),
    DSAWithSHA1("SHA1withDSA"),
    DSAWithSHA256("SHA256withDSA"),
    ECDSAWithSHA1("SHA1withECDSA"),
    ECDSAWithSHA256("SHA256withECDSA"),
    ECDSAWithSHA384("SHA384withECDSA"),
    ECDSAWithSHA512("SHA512withECDSA"),
    SHA256WithRSAPSS("RSAPSSwithSHA256"),
    SHA384WithRSAPSS("RSAPSSwithSHA384"),
    SHA512WithRSAPSS("RSAPSSwithSHA512");

    /**
     * @param standardName
     * @see <a href="https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#signature-algorithms">Standard Signature Algorithm Names</a>
     */
    SignatureAlgorithm(String standardName) {
        this.standardName = standardName;
    }

    @Getter
    private String standardName;
}
