package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.policyspecification.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policyspecification.parser.TPPPolicySpecificationConverter;
import com.venafi.vcert.sdk.utils.VCertConstants;

import java.nio.file.Paths;

public class TppConnectorUtils {

  public static void main(String args[]) {
    String filePath = "/Users/marcos/venafi/repos/vcert-java/src/main/java/com/venafi/vcert/sdk/policyspecification/parser2/marshal/policy_specification.json";
    try {
      TPPPolicySpecificationConverter converter = getConverter(filePath);

      TPPPolicy tppPolicy = converter.convertFromFile(Paths.get(filePath));
      System.out.println("");
    } catch( Exception e){
      e.printStackTrace();
    }
  }

  public static TPPPolicySpecificationConverter getConverter(String filePath) throws VCertException {

    TPPPolicySpecificationConverter converter;

    if (filePath != null) {
      String fileExtension = filePath.substring(filePath.lastIndexOf(".") + 1);

      String convertorKey = fileExtension.equals(VCertConstants.YAML_EXTENSION2) ?  VCertConstants.YAML_EXTENSION : fileExtension;

      converter = TPPPolicySpecificationConverter.getInstance(convertorKey);

      if (converter == null)
        throw new VCertException("Format file is not supported");
    } else
      throw new VCertException("FilePath value is null");

    return converter;
  }

}
