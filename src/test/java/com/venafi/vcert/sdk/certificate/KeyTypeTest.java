package com.venafi.vcert.sdk.certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyTypeTest {

    @ParameterizedTest
    @MethodSource("provideStringsForKeyTypeConversion")
    void keyTypeFromString(String fromString, KeyType expected) {
        assertThat(KeyType.from(fromString)).isEqualTo(expected);
    }

    @Test
    void keyTypeFromUnknownShouldThrowException() {
        assertThrows(IllegalArgumentException.class, () -> KeyType.from("garbage"));
    }

    private static Stream<Arguments> provideStringsForKeyTypeConversion() {
        return Stream.of(
                Arguments.of("rsa", KeyType.RSA),
                Arguments.of("ecdsa", KeyType.ECDSA),
                Arguments.of("ec", KeyType.ECDSA),
                Arguments.of("ecc", KeyType.ECDSA),
                Arguments.of("RSA", KeyType.RSA),
                Arguments.of("ECDSA", KeyType.ECDSA),
                Arguments.of("EC", KeyType.ECDSA),
                Arguments.of("ECC", KeyType.ECDSA)
        );
    }
}