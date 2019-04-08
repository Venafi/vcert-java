package com.venafi.vcert.sdk;

import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Config {
    private ConnectorType connectorType;
    private String baseUrl;
    private String zone;
    private Authentication credentials;
    private String connectionTrust;
    private boolean logVerbose;
    private String configFile;
    private String configSection;
}
