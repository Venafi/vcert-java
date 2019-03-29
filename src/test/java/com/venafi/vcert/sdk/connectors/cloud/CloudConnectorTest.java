package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserAccount;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.endpoint.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CloudConnectorTest {

    @Mock
    private Cloud cloud;
    private CloudConnector classUnderTest;

    @Captor
    private ArgumentCaptor<UserAccount> userAccountArgumentCaptor;

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

    @Test
    @DisplayName("Register a new user on venafi cloud")
    void register() throws  VCertException{
        final String email = "me@venafi.com";
        final Authentication auth =
                new Authentication(null, null, "12345678-1234-1234-1234-123456789012");
        final UserDetails userDetails = mock(UserDetails.class);

        when(cloud.register(eq("12345678-1234-1234-1234-123456789012"), userAccountArgumentCaptor.capture()))
                .thenReturn(userDetails);

        classUnderTest.authenticate(auth);
        classUnderTest.register(email);

        UserAccount userAccount = userAccountArgumentCaptor.getValue();
        assertEquals(userAccount.username(), email);
        assertEquals(userAccount.userAccountType(), "API");
        assertEquals(classUnderTest.user(), userDetails);
    }

}