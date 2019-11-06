package com.venafi.vcert.sdk.connectors;

import com.google.common.annotations.VisibleForTesting;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@VisibleForTesting
public class LockableValue<T> {
  boolean locked;
  T value;
}
