package com.venafi.vcert.sdk.utils;

import java.util.Collection;

public class Is {

    public static boolean blank(Collection collection) {
        return collection == null || collection.isEmpty();
    }

    public static boolean blank(byte[] array) {
        return array == null || array.length == 0;
    }

    /**
     *
     * @param left
     * @param right
     * @return
     * @see <a href="https://stackoverflow.com/questions/41637181/regex-pattern-with-unicode-doesnt-do-case-folding">SO</a>
     * @see <a href="https://www.elastic.co/guide/en/elasticsearch/guide/current/case-folding.html">explanation</a>
     * @see <a href="https://golang.org/pkg/strings/#EqualFold">Go version</a>
     */
    public static boolean equalsFold(String left, String right) {
        return (left != null && right != null && left.toUpperCase().equals(right.toUpperCase()))
                || (left == null && right == null);
    }
}
