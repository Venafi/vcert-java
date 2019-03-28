package com.venafi.vcert.sdk.connectors;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
class LockableValue<T> {
    boolean locked;
    T value;
}
