package com.venafi.vcert.sdk.certificate;

import lombok.Getter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public enum KeySize {

    KS512(512),
    KS1024(1024),
    KS2048(2048),
    KS3072(3072),
    KS4096(4096),
    KS8192(8192);

    private static final Map<Integer, KeySize> LOOKUP = new HashMap<Integer, KeySize>();

    static {
        for (KeySize keySize : KeySize.values()) {
            LOOKUP.put(keySize.value(), keySize);
        }
    }

    public static KeySize from(Integer key) {
        return LOOKUP.get(key);
    }

    public static List<KeySize> allSupportedSizes() {
        return Arrays.asList(KeySize.values());
    }

    @Getter
    private final int value;

    KeySize(int value){
        this.value = value;
    }
}
