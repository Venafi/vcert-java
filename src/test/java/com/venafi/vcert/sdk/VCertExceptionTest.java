package com.venafi.vcert.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VCertExceptionTest {

    @Test
    void throwIfNull() {
        Exception exception = assertThrows(VCertException.class, () -> VCertException.throwIfNull(null, "foo cannot be null"));
        assertEquals("foo cannot be null", exception.getMessage());
    }
}