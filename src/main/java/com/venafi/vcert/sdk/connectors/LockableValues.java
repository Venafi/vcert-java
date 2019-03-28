package com.venafi.vcert.sdk.connectors;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Collection;

@Data
@AllArgsConstructor
class LockableValues<T> {
    boolean locked;
    Collection<T> values;
}
