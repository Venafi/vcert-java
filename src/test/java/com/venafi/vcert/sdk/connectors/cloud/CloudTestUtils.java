package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.policy.domain.*;
import org.apache.commons.lang3.RandomStringUtils;

public class CloudTestUtils {

    public static final String APP_NAME = String.format("VCert-Java-%d-%s", System.currentTimeMillis(), RandomStringUtils.randomAlphabetic(4));

    public static String getRandomZone() {
        return APP_NAME+"\\"+TestUtils.randomCITName();
    }

    public static PolicySpecification getPolicySpecification() {
        PolicySpecification policySpecification = PolicySpecification.builder()
                .policy( Policy.builder()
                        .domains(new String[]{"venafi.com","kwan.com"})
                        .maxValidDays(120)
                        .wildcardAllowed(true)
                        .subject( Subject.builder()
                                .orgs(new String[]{"venafi","kwan"})
                                .orgUnits(new String[]{"DevOps", "OpenSource"})
                                .localities(new String[]{"NewYork","Merida"})
                                .states(new String[]{"NewYork","Yucatan"})
                                .countries(new String[]{"US","MX"})
                                .build())
                        .keyPair( KeyPair.builder()
                                .keyTypes(new String[]{"RSA"})
                                .rsaKeySizes(new Integer[]{1024,2048})
                                .reuseAllowed(true)
                                .build())
                        .subjectAltNames( SubjectAltNames.builder()
                                .dnsAllowed(true)
                                .build())
                        .build())
                .defaults( Defaults.builder()
                        .subject( DefaultsSubject.builder()
                                .org("venafi")
                                .orgUnits(new String[]{"DevOps"})
                                .locality("Merida")
                                .state("Yucatan")
                                .country("MX")
                                .build())
                        .keyPair( DefaultsKeyPair.builder()
                                .keyType("RSA")
                                .rsaKeySize(new Integer(1024))
                                .build())
                        .build())
                .build();
        return policySpecification;
    }

    public static String getVCertExceptionMessage( String message ) {
        return "com.venafi.vcert.sdk.VCertException: " + message;
    }
    public static String getVCertExceptionMessage( String message, String ...attributeNames ) {
        return getVCertExceptionMessage(String.format(message, attributeNames));
    }
}
