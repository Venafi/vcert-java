package com.venafi.vcert.sdk.policyspecification.api.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AttributeLockable<T> {
    private T[] values;
    private boolean lock;
}
