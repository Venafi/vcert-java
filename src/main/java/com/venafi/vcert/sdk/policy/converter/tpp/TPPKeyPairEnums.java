package com.venafi.vcert.sdk.policy.converter.tpp;

import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.KeySize;

import java.util.HashMap;
import java.util.Map;

public class TPPKeyPairEnums {

    private static Map<String, KeyType> keyTypeMap = new HashMap<String, KeyType>();
    private static Map<Integer, KeySize> rsaKeySizeMap = new HashMap<Integer, KeySize>();
    private static Map<String, EllipticCurve> ellipticCurveMap = new HashMap<String, EllipticCurve>();

    static {
        keyTypeMap.put(KeyType.RSA.value(), KeyType.RSA);
        keyTypeMap.put(KeyType.ECDSA.value(), KeyType.ECDSA);
    }

    static {
        rsaKeySizeMap.put(KeySize.KS512.value(), KeySize.KS512);
        rsaKeySizeMap.put(KeySize.KS1024.value(), KeySize.KS1024);
        rsaKeySizeMap.put(KeySize.KS2048.value(), KeySize.KS2048);
        rsaKeySizeMap.put(KeySize.KS3072.value(), KeySize.KS3072);
        rsaKeySizeMap.put(KeySize.KS4096.value(), KeySize.KS4096);
    }

    static {
        ellipticCurveMap.put(EllipticCurve.EllipticCurveP256.value(), EllipticCurve.EllipticCurveP256);
        ellipticCurveMap.put(EllipticCurve.EllipticCurveP384.value(), EllipticCurve.EllipticCurveP384);
        ellipticCurveMap.put(EllipticCurve.EllipticCurveP521.value(), EllipticCurve.EllipticCurveP521);
    }

    public static boolean containsKeyTypes(String[] types){

        for (String type : types) {
            if(!containsKeyType(type))
                return false;
        }

        return true;
    }

    public static boolean containsKeyType(String value){
        KeyType keyType = null;
        try {
            keyType = KeyType.from(value);
        } catch (IllegalArgumentException e){
            return false;
        }

        return keyTypeMap.containsKey(keyType.value());
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

    public static boolean containsEllipticCurves(String[] curves){

        for (String curve : curves) {
            if(!containsEllipticCurve(curve))
                return false;
        }

        return true;
    }

    public static boolean containsEllipticCurve(String value){
        return ellipticCurveMap.containsKey(value);
    }

    public static EllipticCurve getEllipticCurve(String value){
        return ellipticCurveMap.get(value);
    }
}
