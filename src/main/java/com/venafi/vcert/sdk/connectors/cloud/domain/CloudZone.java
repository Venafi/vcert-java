package com.venafi.vcert.sdk.connectors.cloud.domain;

import com.venafi.vcert.sdk.VCertException;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

public class CloudZone {

    @Getter private String zone;
    @Getter private String appName;
    @Getter private String citAlias;

    public CloudZone(String zone ) throws VCertException {
        this.zone = zone;
        String values[] = StringUtils.split(zone, "\\");

        if( values == null || values.length < 2)
            throw new VCertException("The zone is not corrected formatted. It should be at the way of AppName\\CitAlias");

        appName = values[0];
        citAlias = values[1];
    }
}
