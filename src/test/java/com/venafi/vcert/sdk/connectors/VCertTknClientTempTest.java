package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class VCertTknClientTempTest {

    public static void main(String args[]){

        final Authentication auth = Authentication.builder()
                .accessToken("eZ8h+WTimKfYkSQqxjVbwg==")
                //.scope("configuration:manage")
                //.clientId("api-all-access")
                .build();

        /*Authentication auth = Authentication.builder()
                .user("admin")
                .password("newPassw0rd!")
                //.clientId("api-all-access")
                //.scope("configuration:manage")
                .build();*/

        final Config config = Config.builder()
                .connectorType(ConnectorType.TPP_TOKEN)
                .baseUrl("https://supertreat.venqa.venafi.com/")
                .credentials(auth)
                .build();

        try {
            final VCertTknClient client = new VCertTknClient(config);
            //TokenInfo tknInfo = client.getAccessToken(auth);
            //ZoneConfiguration zoneConfiguration = client.readZoneConfiguration("Certificates\\vcert\\");


            String filePath = "/Users/marcos/venafi/repos/vcert-java/src/main/java/com/venafi/vcert/sdk/policyspecification/parser2/marshal/policy_specification.json";
            String targetFilePath = "/Users/marcos/venafi/repos/vcert-java/src/main/java/com/venafi/vcert/sdk/policyspecification/parser2/marshal/policy_specification03.json";
            //String content = new Scanner(new File(filePath)).useDelimiter("\\Z").next();



            client.setPolicy("Amoo\\amoo25", Paths.get(filePath));

            client.getPolicySpecificationFile("Amoo\\amoo25", Paths.get(targetFilePath));

        } catch ( Exception e) {
            e.printStackTrace();
        }


    }
}
