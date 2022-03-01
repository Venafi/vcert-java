package com.venafi.vcert.sdk.features;

import com.venafi.vcert.sdk.certificate.KeySize;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class SupportedRSAKeySizes {
	
	public static final SupportedRSAKeySizes TPP = new SupportedRSAKeySizes(List.of(KeySize.KS512, KeySize.KS1024, KeySize.KS2048, KeySize.KS3072, KeySize.KS4096));
	public static final SupportedRSAKeySizes VAAS = new SupportedRSAKeySizes(List.of(KeySize.KS1024, KeySize.KS2048, KeySize.KS4096));
    
    private Map<Integer, KeySize> rsaKeySizeMap;
    
    public SupportedRSAKeySizes(List<KeySize> keySizes) {
    	rsaKeySizeMap = keySizes.stream().collect(Collectors.toMap(KeySize::value, Function.identity()));
    }

    public boolean containsRsaKeySizes(Integer[] sizes){

        for (int size : sizes) {
            if(!containsRsaKeySize(size))
                return false;
        }

        return true;
    }

    public boolean containsRsaKeySize(int value){
        return rsaKeySizeMap.containsKey(value);
    }

    public KeySize getRsaKeySize(int value){
        return rsaKeySizeMap.get(value);
    }
}
