package com.venafi.vcert.sdk.connectors;

import java.util.List;
import com.google.common.annotations.VisibleForTesting;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@VisibleForTesting
public class LockableValues<T> {
  boolean locked;
  List<T> values;
}
