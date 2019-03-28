package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.connectors.Policy;
import lombok.Data;

import java.util.Collection;
import java.util.Map;

@Data
public class ZoneConfiguration {

    private String organization;
    private Collection<String> organizationalUnit;
    private String country;
    private String province;
    private String locality;
    private Policy policy;

    private SignatureAlgorithm hashAlgorithm;

    private Map<String, String> customAttributeValues;

}


