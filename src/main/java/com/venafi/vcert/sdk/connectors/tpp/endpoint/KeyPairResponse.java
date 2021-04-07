package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class KeyPairResponse {
    @SerializedName("KeyAlgorithm")
    private SingleValueAttribute<String> keyAlgorithm;
    @SerializedName("KeySize")
    private SingleValueAttribute<Integer> keySize;
    @SerializedName("EllipticCurve")
    private SingleValueAttribute<String> ellipticCurve;
}
