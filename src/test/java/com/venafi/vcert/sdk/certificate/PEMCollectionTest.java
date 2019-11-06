package com.venafi.vcert.sdk.certificate;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import com.venafi.vcert.sdk.VCertException;

class PEMCollectionTest {

  @Test
  void fromResponse() throws VCertException, IOException {
    ClassLoader classLoader = getClass().getClassLoader();
    String path = classLoader.getResource("certificates/certWithKey.pem").getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    String body = new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore);
    assertThat(pemCollection.certificate()).isNotNull();
    assertThat(pemCollection.chain()).hasSize(0);
    assertThat(pemCollection.privateKey()).isNotNull();
  }
}
