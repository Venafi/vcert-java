package com.venafi.vcert.sdk.connectors;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Collection;
import java.util.List;

@Data
@AllArgsConstructor
class LockableValues<T> {
    boolean locked;
    List<T> values;
}
