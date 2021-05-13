package com.venafi.vcert.sdk.connectors.tpp.endpoint;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class MultiValueAttribute<T> {
    @SerializedName("Values")
    private T[] values;
    @SerializedName("Locked")
    private boolean locked;
}
