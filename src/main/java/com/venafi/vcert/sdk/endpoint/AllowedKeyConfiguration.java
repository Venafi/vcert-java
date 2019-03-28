package com.venafi.vcert.sdk.endpoint;

import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import lombok.Data;

import java.util.Collection;

@Data
public class AllowedKeyConfiguration {
    private KeyType keytype;
    private Collection<Integer> keySizes;
    private Collection<EllipticCurve> keyCurves;
}
