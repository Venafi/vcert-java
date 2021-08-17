package com.venafi.vcert.sdk.connectors.tpp;

import java.time.Instant;

import com.venafi.vcert.sdk.TestUtils;
import com.venafi.vcert.sdk.policy.domain.*;

public class TppTestUtils {

    public static String getRandomZone() {
        return TestUtils.TPP_PM_ROOT+"\\"+TestUtils.randomCITName();
    }

    public static PolicySpecification getPolicySpecification() {
        PolicySpecification policySpecification = PolicySpecification.builder()
                .policy( Policy.builder()
                        .domains(new String[]{"venafi.com","kwan.com"})
                        .certificateAuthority(TestUtils.TPP_CA_NAME)
                        .wildcardAllowed(true)
                        .subject( Subject.builder()
                                .orgs(new String[]{"venafi"})
                                .orgUnits(new String[]{"DevOps"})
                                .localities(new String[]{"Merida"})
                                .states(new String[]{"Yucatan"})
                                .countries(new String[]{"MX"})
                                .build())
                        .keyPair( KeyPair.builder()
                                .keyTypes(new String[]{"RSA"})
                                .rsaKeySizes(new Integer[]{1024})
                                .serviceGenerated(true)
                                .reuseAllowed(true)
                                .build())
                        .subjectAltNames( SubjectAltNames.builder()
                                .dnsAllowed(false)
                                .ipAllowed(false)
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
                                .rsaKeySize(Integer.valueOf(1024))
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
    
    public static String getRandSshKeyId() {
    	return String.format("vcert-java-%d-SSHCert", Instant.now().getEpochSecond());
    }
}
