package com.venafi.vcert.sdk.utils;

import java.util.Collection;

public class Is {

    public static boolean blank(Collection collection) {
        return collection == null || collection.isEmpty();
    }
}
