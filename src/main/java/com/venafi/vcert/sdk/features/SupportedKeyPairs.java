package com.venafi.vcert.sdk.features;

import com.venafi.vcert.sdk.certificate.KeyType;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class SupportedKeyPairs {
	
	public static final SupportedKeyPairs TPP = new SupportedKeyPairs(List.of(KeyType.RSA, KeyType.ECDSA));
	public static final SupportedKeyPairs VAAS = new SupportedKeyPairs(List.of(KeyType.RSA));
    
    private Map<String, KeyType> keyTypeMap;
    
    public SupportedKeyPairs(List<KeyType> keyTypes) {
    	keyTypeMap = keyTypes.stream().collect(Collectors.toMap(KeyType::value, Function.identity()));
    }

    public boolean containsKeyTypes(String[] types){

        for (String type : types) {
            if(!containsKeyType(type))
                return false;
        }

        return true;
    }

    public boolean containsKeyType(String value){
        KeyType keyType = null;
        try {
            keyType = KeyType.from(value);
        } catch (IllegalArgumentException e){
            return false;
        }

        return keyTypeMap.containsKey(keyType.value());
    }

    public KeyType getKeyType(String value){
        return keyTypeMap.get(KeyType.from(value).value());
    }
}
