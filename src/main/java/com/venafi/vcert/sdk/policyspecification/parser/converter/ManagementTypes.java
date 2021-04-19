package com.venafi.vcert.sdk.policyspecification.parser.converter;

import java.util.HashMap;
import java.util.Map;

public enum ManagementTypes {
    PROVISIONING("Provisioning", true),
    ENROLLMENT("Enrollment", false);

    private static final Map<String, ManagementTypes> ENUMS = new HashMap<String, ManagementTypes>();

    static {
        for (ManagementTypes managementType : ManagementTypes.values())
            ENUMS.put(managementType.value, managementType);
    }

    public static ManagementTypes from(String value ){
        return ENUMS.get(value);
    }
    public static ManagementTypes from(Boolean psValue ){
        return psValue ? PROVISIONING : ENROLLMENT;
    }

    public final String value;
    public final Boolean psValue;

    ManagementTypes(String value, Boolean psValue){
        this.value = value;
        this.psValue = psValue;
    }
}
