package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CloudConnectorTest {

    @Mock
    private Cloud cloud;
    private CloudConnector classUnderTest;

    @BeforeEach
    void setUp() {
        classUnderTest = new CloudConnector(cloud);
    }

    @Test
    void authenticates() throws VCertException {
        UserDetails response = new UserDetails();
        when(cloud.authorize(anyString())).thenReturn(response);

        Authentication auth = new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        classUnderTest.authenticate(auth);
        assertEquals(response, classUnderTest.user());
    }

}