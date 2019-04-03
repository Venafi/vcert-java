package com.venafi.vcert.sdk.certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class EllipticCurveTest {

    @ParameterizedTest
    @MethodSource("provideStringsForEllipiticCurveConversion")
    void ellipticCurveFromString(String fromString, String bcName, EllipticCurve expected) {
        assertThat(EllipticCurve.from(fromString).bcName()).isEqualTo(bcName);
        assertThat(EllipticCurve.from(fromString)).isEqualTo(expected);
    }

    @Test
    void ellipticCurveFromUnknownShouldReturnDefault() {
        assertThat(EllipticCurve.from("garbage")).isEqualTo(EllipticCurve.EllipticCurveP521);
    }

    private static Stream<Arguments> provideStringsForEllipiticCurveConversion() {
        return Stream.of(
                Arguments.of("P224", "P-224", EllipticCurve.EllipticCurveP224),
                Arguments.of("p224", "P-224", EllipticCurve.EllipticCurveP224),
                Arguments.of("P256", "P-256", EllipticCurve.EllipticCurveP256),
                Arguments.of("p256", "P-256", EllipticCurve.EllipticCurveP256),
                Arguments.of("P384", "P-384", EllipticCurve.EllipticCurveP384),
                Arguments.of("p384", "P-384", EllipticCurve.EllipticCurveP384),
                Arguments.of("P521", "P-521", EllipticCurve.EllipticCurveP521),
                Arguments.of("p521", "P-521", EllipticCurve.EllipticCurveP521)
        );
    }
}