package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import feign.FeignException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CloudConnectorAT {

    private CloudConnector classUnderTest;

    @BeforeEach
    public void authenticate() throws VCertException {
        Cloud cloud = Cloud.connect(System.getenv("VENAFI_CLOUD_URL"));
        classUnderTest = new CloudConnector(cloud);
        Authentication authentication = new Authentication(null, null, System.getenv("VENAFI_API_KEY"));
        classUnderTest.authenticate(authentication);
    }

    @Test
    void readZoneConfiguration() throws VCertException {
        try {
            ZoneConfiguration zoneConfiguration = classUnderTest.readZoneConfiguration(System.getenv("VENAFI_ZONE"));
        } catch(FeignException fe) {
            throw VCertException.fromFeignException(fe);
        }
    }
}