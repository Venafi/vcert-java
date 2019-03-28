package com.venafi.vcert.sdk.connectors;


import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;


public class ZoneConfigurationTest {

    @Test
    public void algos() {
        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName() + " version: " + provider.getVersion());
            for (Provider.Service service : provider.getServices()) {
                System.out.printf("  Type : %-30s  Algorithm: %-30s\n", service.getType(), service.getAlgorithm());
            }
        }
        System.out.println("===");
        Provider[] providers = Security.getProviders(Collections.singletonMap("Signature.MD2withRSA", ""));
        Arrays.stream(providers).forEach(System.out::println);
    }

}