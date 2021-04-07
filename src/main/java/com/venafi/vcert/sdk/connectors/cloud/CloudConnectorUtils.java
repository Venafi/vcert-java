package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.policyspecification.parser.CloudPolicySpecificationConverter;
import com.venafi.vcert.sdk.utils.VCertConstants;

public class CloudConnectorUtils {

    public static CloudPolicySpecificationConverter getConverter(String filePath) throws VCertException {

      CloudPolicySpecificationConverter converter;

      if (filePath != null) {
        String fileExtension = filePath.substring(filePath.lastIndexOf(".") + 1);

        String convertorKey = fileExtension.equals(VCertConstants.YAML_EXTENSION2) ?  VCertConstants.YAML_EXTENSION : fileExtension;

        converter = CloudPolicySpecificationConverter.getInstance(convertorKey);

        if (converter == null)
          throw new VCertException("Format file is not supported");
      }else
        throw new VCertException("FilePath value is null");

      return converter;
    }

}
