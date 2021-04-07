package com.venafi.vcert.sdk.policyspecification.parser.marshal;

public class VCertMarshalException extends Exception{

    public VCertMarshalException() {
    }

    public VCertMarshalException(String message) {
        super(message);
    }

    public VCertMarshalException(String message, Throwable cause) {
        super(message, cause);
    }

    public VCertMarshalException(Throwable cause) {
        super(cause);
    }

    public VCertMarshalException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
