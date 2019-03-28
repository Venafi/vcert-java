package com.venafi.vcert.sdk.certificate;

import java.util.Arrays;
import java.util.Collection;

public enum KeyType {
    RSA, ECDSA;

    public static KeyType set(String value) {
        switch (value.toLowerCase()) {
            case "rsa": return RSA;
            case "ecdsa":
            case "ec":
            case "ecc": return ECDSA;
            default: throw new IllegalArgumentException(String.format("unknown key type: %s", value));
        }
    }

    public static Collection<Integer> allSupportedKeySizes() {
        return Arrays.asList(512, 1024, 2048, 4096, 8192);
    }

    public static Integer defaultRsaLength() {
        return 2048;
    }
}
