package com.venafi.vcert.sdk.example.policymanagement;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertTknClient;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.policy.domain.*;
import com.venafi.vcert.sdk.policy.domain.Policy;

/**
 * The following example is to show how to use the policy management feature
 * in order to create/update and get a policy for both TPP and Cloud (OutagePredict)
 */
public class PolicyManagementBuilderExample {

    public static void main(String args[]){

        try {
            String ca = "<TPP_CA_NAME>";
            String policyName = "<TPP_POLICY_MANAGEMENT_SAMPLE>";
            String user = "<TPPUSER>";
            String password = "<TPPPASSWORD>";
            String baseUri = "<TPP_URL>";

            //1. Get an instance of com.venafi.vcert.sdk.policy.domain.PolicySpecification class.
            //That can be done using the builder provided by the PolicySpecification

            PolicySpecification policySpecification = PolicySpecification.builder()
                    .policy( Policy.builder()
                            .domains(new String[]{"venafi.com"})
                            .maxValidDays(120)
                            .certificateAuthority(ca)
                            .wildcardAllowed(true)
                            .subject( Subject.builder()
                                    .orgs(new String[]{"venafi"})
                                    .orgUnits(new String[]{"DevOps", "OpenSource"})
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
                                    .emailAllowed(true)
                                    .build())
                            .build())
                    .build();

            //2. Get a VCertClient. For this time, it is being to use a VCertClient for TPP.
            Authentication auth = Authentication.builder()
                    .user(user)
                    .password(password)
                    .clientId("api-all-access")
                    .scope("certificate:manage;configuration:manage")
                    .build();


            Config config = Config.builder()
                    .connectorType(ConnectorType.TPP_TOKEN)
                    .baseUrl(baseUri)
                    .build();

            VCertTknClient client = new VCertTknClient(config);
            client.getAccessToken(auth);

            //3. Use the VCertClient method setPolicy() to set a Policy.
            // If the the policy doesn't exist then it will be created.
            // If the the policy exists then it will be updated.

            client.setPolicy(policyName, policySpecification);

            //4. You can get the Policy which you created/updated using the getPolicy method
            PolicySpecification policyTemp = client.getPolicy(policyName);

            //5. Then use it to write it in Yaml format.
            // This time we will use the Jackson parser to get the Yaml string.
            // You can learn more about Jackson parser in https://github.com/FasterXML/jackson
            //and http://tutorials.jenkov.com/java-json/jackson-objectmapper.html
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            String policyAsString = mapper.writeValueAsString(policyTemp);

            System.out.println(policyAsString);

            client.revokeAccessToken();

        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
}
