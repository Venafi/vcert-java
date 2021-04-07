package com.venafi.vcert.sdk.policyspecification.parser;

import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;
import com.venafi.vcert.sdk.policyspecification.parser.converter.IPolicySpecificationAPIConverter;
import com.venafi.vcert.sdk.policyspecification.parser.marshal.IPolicySpecificationMarshal;
import com.venafi.vcert.sdk.policyspecification.parser.validator.IPolicySpecificationValidator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public abstract class PolicySpecificationConverter<T> {

    public T convertFromFile(Path filePath) throws Exception{

        String content = new Scanner( filePath ).useDelimiter("\\Z").next();

        return convertFromString(content);
    }

    public T convertFromString(String content) throws Exception{

        PolicySpecification policySpecification = getPolicySpecificationMarshal().unmarshal(content);

        return convertFromPolicySpecification(policySpecification);
    }

    public T convertFromPolicySpecification(PolicySpecification policySpecification) throws Exception{

        getPolicySpecificationValidator().validate(policySpecification);

        return getPolicySpecificationAPIConverter().convert(policySpecification);
    }

    public PolicySpecification convertToPolicySpecification(T t) throws Exception{
        return getPolicySpecificationAPIConverter().convert(t);
    }

    public String convertToString(T t) throws Exception{

        PolicySpecification policySpecification = convertToPolicySpecification(t);

        return getPolicySpecificationMarshal().marshal(policySpecification);
    }

    public File convertToFile(T t, Path filePath) throws Exception {

        String policySpecificationString = convertToString( t );

        Files.write(filePath, policySpecificationString.getBytes());

        return filePath.toFile();
    }

    //1 Parse json
    //2 custom validation
    //3 build custom object

    protected abstract IPolicySpecificationMarshal getPolicySpecificationMarshal();

    protected abstract IPolicySpecificationValidator getPolicySpecificationValidator();

    protected abstract IPolicySpecificationAPIConverter<T> getPolicySpecificationAPIConverter();

}
