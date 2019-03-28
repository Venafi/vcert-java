package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TppConnectorAT {

    private TppConnector classUnderTest = new TppConnector(Tpp.connect(System.getenv("VENAFI_TPP_URL")));

    @BeforeEach
    void authenticate() throws VCertException {
        Authentication authentication = new Authentication(System.getenv("VENAFI_USER"), System.getenv("VENAFI_PASSWORD"), null);
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            ZoneConfiguration zoneConfig = classUnderTest.readZoneConfiguration(System.getenv("VENAFI_ZONE"));
        } catch (FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }
}