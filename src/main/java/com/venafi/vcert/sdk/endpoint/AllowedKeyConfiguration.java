package com.venafi.vcert.sdk.endpoint;

import java.util.List;
import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AllowedKeyConfiguration {
  @SerializedName("keytype") // todo: check server response for spelling
  private KeyType keyType;
  private List<Integer> keySizes;
  private List<EllipticCurve> keyCurves;
}
