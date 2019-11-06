package com.venafi.vcert.sdk.certificate;

public enum ChainOption {
  // ChainOptionRootLast specifies the root certificate should be in the last position of the chain
  ChainOptionRootLast,
  // ChainOptionRootFirst specifies the root certificate should be in the first position of the
  // chain
  ChainOptionRootFirst,
  // ChainOptionIgnore specifies the chain should be ignored
  ChainOptionIgnore;

  public static ChainOption fromString(String order) {
    switch (order.toLowerCase()) {
      case "root-first":
        return ChainOptionRootFirst;
      case "ignore":
        return ChainOptionIgnore;
      default:
        return ChainOptionRootLast;
    }
  }
}
