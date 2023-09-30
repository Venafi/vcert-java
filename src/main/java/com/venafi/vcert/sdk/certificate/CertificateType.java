package com.venafi.vcert.sdk.certificate;


import lombok.Getter;

public enum CertificateType {
    Auto("Auto"),
    CodeSigning("Code Signing: X.509 Code Signing Certificate"),
    Device("Device: X.509 Device Certificate"),
    Server("Server: X.509 Server Certificate"),
    User("User: X.509 User Certificate");

    public static CertificateType from(String value) {
        switch (value.toLowerCase()) {
            case "auto":
                return Auto;
            case "code signing: x.509 code signing certificate":
                return CodeSigning;
            case "device: x.509 device certificate":
                return Device;
            case "server: x.509 server certificate":
                return Server;
            case "user: x.509 user certificate":
                return User;
            default:
                throw new IllegalArgumentException(String.format("unknown certificate type: %s", value));
        }
    }

    @Getter
    private final String value;

    CertificateType(String value) {
        this.value = value;
    }
}