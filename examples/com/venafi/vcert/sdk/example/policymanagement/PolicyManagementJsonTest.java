package com.venafi.vcert.sdk.policy;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertClient;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

import java.io.File;
import java.net.URL;

/**
 * The following test is to show how to use the policy management feature
 * in order to create/update and get a policy for both TPP and Cloud (OutagePredict)
 */
public class PolicyManagementJsonTest {

    public static void main(String args[]){

        try {

            String policyName = "<APP_NAME>\\<CIT_ALIAS>";//replace it by the policy full name
            String tppl_api_key = "<APIKEY>";//replace it by the api-key
            String json_source_file = "<PARENT_PATH>/policy_specification.json";//replace it by the path where the policy_specification.json file will be
            String json_target_file = "<PARENT_PATH>/policy_specification_result.json";//replace it by the path where the policy_specification_result.json file will be

            //1. Get an instance of com.venafi.vcert.sdk.policy.domain.PolicySpecification class.
            // At this time it will be used the Jackson parser to get an instance of PolicySpecification given a Json file.
            // You can learn more about Jackson parser in https://github.com/FasterXML/jackson
            //and http://tutorials.jenkov.com/java-json/jackson-objectmapper.html

            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            PolicySpecification policySpecification = mapper.readValue( new File(json_source_file), PolicySpecification.class);

            //2. Get a VCertClient. For this time, it will used a VCertClient for Cloud.
            Authentication auth = Authentication.builder()
                    .apiKey(tppl_api_key)
                    .build();

            Config config = Config.builder()
                    .connectorType(ConnectorType.CLOUD)
                    .build();

            VCertClient client = new VCertClient(config);
            client.authenticate(auth);

            //3. Use the VCertClient method setPolicy() to set a Policy.
            // If the the policy doesn't exist then that will be created.
            // If the the policy exists then it will updated.

            client.setPolicy(policyName, policySpecification);

            //4. You can get the Policy which you created/updated using the getPolicy method and then use it
            //to write it in json format using the Jackson parser.
            PolicySpecification policyTemp = client.getPolicy(policyName);

            mapper.writeValue(new File(json_target_file), policyTemp);

        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
}
