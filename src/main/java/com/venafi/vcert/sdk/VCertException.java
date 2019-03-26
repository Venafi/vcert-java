package com.venafi.vcert.sdk;

public class VCertException extends Exception {

    public VCertException(String message) {
        super(message);
    }

    public VCertException() {
        super();
    }

    public VCertException(String message, Exception cause) {
        super(message, cause);
    }

    public static void throwIfNull(Object testee, String message) throws VCertException {
        if(testee != null) {
            return;
        }
        if(message != null) {
            throw new VCertException(message);
        }
        throw new VCertException();
    }
}
