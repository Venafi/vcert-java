package com.venafi.vcert.sdk.certificate;

import lombok.Getter;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public enum EllipticCurve {
    EllipticCurveP521("P521"), EllipticCurveP384("P384"), EllipticCurveP256("P256"), EllipticCurveP224("P224");

    @Getter
    private final String value;

    EllipticCurve(String value) {
        this.value = value;
    }

    private static Map<String, EllipticCurve> LOOKUP = new HashMap<>(EllipticCurve.values().length);

    static {
        for(EllipticCurve curve : EllipticCurve.values()) {
            LOOKUP.put(curve.value().toLowerCase(), curve);
        }
    }

    public static EllipticCurve set(String value) {
        if(LOOKUP.containsKey(value.toLowerCase())) {
            return LOOKUP.get(value.toLowerCase());
        }
        return ellipticCurveDefault();
    }

    public static EllipticCurve ellipticCurveDefault() {
        return EllipticCurveP521;
    }

    public static Collection<EllipticCurve> allSupportedCures() {
        return Arrays.asList(EllipticCurve.values());
    }
}
