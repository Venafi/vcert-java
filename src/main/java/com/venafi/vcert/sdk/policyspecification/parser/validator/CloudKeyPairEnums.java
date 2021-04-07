package com.venafi.vcert.sdk.policyspecification.parser.validator;

import com.venafi.vcert.sdk.certificate.KeySize;
import com.venafi.vcert.sdk.certificate.KeyType;

import java.util.HashMap;
import java.util.Map;

public class CloudKeyPairEnums {

    private static Map<String, KeyType> keyTypeMap = new HashMap<String, KeyType>();
    private static Map<Integer, KeySize> rsaKeySizeMap = new HashMap<Integer, KeySize>();

    static {
        keyTypeMap.put(KeyType.RSA.value(), KeyType.RSA);
    }

    static {
        rsaKeySizeMap.put(KeySize.KS1024.value(), KeySize.KS1024);
        rsaKeySizeMap.put(KeySize.KS2048.value(), KeySize.KS2048);
        rsaKeySizeMap.put(KeySize.KS4096.value(), KeySize.KS4096);
    }

    public static boolean containsKeyTypes(String[] types){

        for (String type : types) {
            if(!containsKeyType(type))
                return false;
        }

        return true;
    }

    public static boolean containsKeyType(String value){
        return keyTypeMap.containsKey(KeyType.from(value).value());
    }

    public static KeyType getKeyType(String value){
        return keyTypeMap.get(KeyType.from(value).value());
    }

    public static boolean containsRsaKeySizes(Integer[] sizes){

        for (int size : sizes) {
            if(!containsRsaKeySize(size))
                return false;
        }

        return true;
    }

    public static boolean containsRsaKeySize(int value){
        return rsaKeySizeMap.containsKey(value);
    }

    public static KeySize getRsaKeySize(int value){
        return rsaKeySizeMap.get(value);
    }

}
