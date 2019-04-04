package com.venafi.vcert.sdk.connectors;

import com.google.common.annotations.VisibleForTesting;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
@VisibleForTesting
public class LockableValues<T> {
    boolean locked;
    List<T> values;
}
