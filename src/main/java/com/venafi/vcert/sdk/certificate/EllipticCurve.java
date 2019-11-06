package com.venafi.vcert.sdk.certificate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;

public enum EllipticCurve {
  EllipticCurveP224("P224", "P-224"),
  EllipticCurveP256("P256", "P-256"),
  EllipticCurveP384("P384", "P-384"),
  EllipticCurveP521("P521", "P-521");

  @Getter
  private final String value;

  @Getter
  private final String bcName;

  EllipticCurve(String value, String bcName) {
    this.value = value;
    this.bcName = bcName;
  }

  private static Map<String, EllipticCurve> LOOKUP = new HashMap<>(EllipticCurve.values().length);

  static {
    for (EllipticCurve curve : EllipticCurve.values()) {
      LOOKUP.put(curve.value().toLowerCase(), curve);
    }
  }

  public static EllipticCurve from(String value) {
    if (LOOKUP.containsKey(value.toLowerCase())) {
      return LOOKUP.get(value.toLowerCase());
    }
    return ellipticCurveDefault();
  }

  public static EllipticCurve ellipticCurveDefault() {
    return EllipticCurveP521;
  }

  public static List<EllipticCurve> allSupportedCures() {
    return Arrays.asList(EllipticCurve.values());
  }
}
