package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertClient;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.policyspecification.domain.Defaults;
import com.venafi.vcert.sdk.policyspecification.domain.DefaultsKeyPair;
import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class VCertTknClientTempTest {

    public static void main(String args[]){

        try {
            //testVcertTknClientUsingFile(client);
            //testVcertTknClientUsingFileMinimalVersion();
            testVcertClientCloudUsingFile();
            //testVcertClientCloudUsingFileMinimalVersion();

        } catch ( Exception e) {
            e.printStackTrace();
        }
    }

    public static void testVcertTknClientUsingFile() throws VCertException {
        String policyName = "Amoo\\amoo25";
        String filePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/policy_specification.json";
        String targetFilePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/returned_ps_from_VcertTknClient_01.json";
        String token = "eZ8h+WTimKfYkSQqxjVbwg==";
        String baseUri = "https://supertreat.venqa.venafi.com/";

        testUsingFile(policyName, filePath, targetFilePath, ConnectorType.TPP_TOKEN, token, baseUri);
    }

    public static void testVcertTknClientUsingFileMinimalVersion() throws VCertException {
        String policyName = "Amoo\\amoo25";
        String filePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/tpp-minimal.json";
        String targetFilePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/returned_minimal_ps_from_VcertTknClient_01.json";
        String token = "eZ8h+WTimKfYkSQqxjVbwg==";
        String baseUri = "https://supertreat.venqa.venafi.com/";

        testUsingFile(policyName, filePath, targetFilePath, ConnectorType.TPP_TOKEN, token, baseUri);
    }

    public static void testVcertClientCloudUsingFile() throws VCertException {
        String policyName = "vcert-marcos-0002\\marcos-test06";
        String filePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/cloud_policy_specification.json";
        String targetFilePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/returned_ps_from_VcertCloudClient_01.json";
        String tppl_api_key = "09b21986-6378-47b6-802a-763980219bf7";

        testUsingFile(policyName, filePath, targetFilePath, ConnectorType.CLOUD, tppl_api_key, null);
    }

    public static void testVcertClientCloudUsingFileMinimalVersion() throws VCertException {
        String policyName = "vcert-marcos-0002\\marcos-test03";
        String filePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/cloud-minimal02.json";
        String targetFilePath = "/Users/marcos/venafi/repos/vcert-java/src/test/java/com/venafi/vcert/sdk/connectors/returned_minimal_ps_from_VcertCloudClient_01.json";
        String tppl_api_key = "09b21986-6378-47b6-802a-763980219bf7";

        testUsingFile(policyName, filePath, targetFilePath, ConnectorType.CLOUD, tppl_api_key, null);
    }

    public static void testUsingFile( String policyName, String sourceFilePath, String targetFilePath, ConnectorType connectorType, String authKey, String baseUrl) throws VCertException {
        Authentication auth;
        if( ConnectorType.CLOUD == connectorType )
            auth = Authentication.builder()
                .apiKey(authKey)
                .build();
        else
            auth = Authentication.builder()
                    .accessToken(authKey)
                    .build();

        Config config;
        if( ConnectorType.CLOUD == connectorType )
            config = Config.builder()
                    .connectorType(connectorType)
                    .credentials(auth)
                    .build();
        else
            config = Config.builder()
                    .connectorType(connectorType)
                    .baseUrl(baseUrl)
                    .credentials(auth)
                    .build();

        if (ConnectorType.TPP_TOKEN == connectorType ) {
            VCertTknClient client = new VCertTknClient(config);
            client.setPolicy(policyName, Paths.get(sourceFilePath));

            if(targetFilePath != null)
                client.getPolicySpecificationFile(policyName, Paths.get(targetFilePath));
        } else {
            VCertClient client = new VCertClient(config);
            client.authenticate(auth);
            client.setPolicy(policyName, Paths.get(sourceFilePath));

            if(targetFilePath != null)
                client.getPolicySpecificationFile(policyName, Paths.get(targetFilePath));
        }
    }
}
