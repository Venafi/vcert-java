package com.venafi.vcert.sdk.policyspecification.parser.converter;

import java.util.HashMap;
import java.util.Map;

public enum AltName {
    DNS("DNS"),
    IP("IP"),
    EMAIL("Email"),
    URI("URI"),
    UPN("UPN");

    private static final Map<String, AltName> ENUMS = new HashMap<String, AltName>();

    static {
        for (AltName altName : AltName.values())
            ENUMS.put(altName.value, altName);
    }

    public static AltName from(String value ){
        return ENUMS.get(value);
    }

    public final String value;

    AltName(String value){
        this.value = value;
    }
}
