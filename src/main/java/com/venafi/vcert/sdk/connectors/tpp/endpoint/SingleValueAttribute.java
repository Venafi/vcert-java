package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class SingleValueAttribute<T> {
    @SerializedName("Value")
    private T value;
    @SerializedName("Locked")
    private boolean locked;
}
