package com.venafi.vcert.sdk.policy.api.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AttributeLockable<T> {
    private T[] values;
    private boolean lock;
}
