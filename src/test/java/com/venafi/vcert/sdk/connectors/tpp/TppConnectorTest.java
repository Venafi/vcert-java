package com.venafi.vcert.sdk.connectors.tpp;


import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TppConnectorTest {

    @Mock
    private Tpp tpp;
    private TppConnector classUnderTest;

    @BeforeEach
    void setUp() {
        this.classUnderTest = new TppConnector(tpp);
    }

    @Test
    void canGetAuthToken() throws VCertException {
        AuthorizeResponse response = new AuthorizeResponse().apiKey("12345678-1234-1234-1234-123456789012").validUntil(OffsetDateTime.now());
        when(tpp.authorize(any(TppConnector.AuthorizeRequest.class))).thenReturn(response);

        Authentication authentication = new Authentication("user", "pass", null);
        classUnderTest.authenticate(authentication);
        assertNotNull(classUnderTest.apiKey());
    }

}