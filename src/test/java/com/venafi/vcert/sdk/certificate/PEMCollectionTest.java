package com.venafi.vcert.sdk.certificate;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import com.venafi.vcert.sdk.VCertException;

class PEMCollectionTest {
  private static final String KEY_PASSWORD = "my secret";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private String readResourceAsString(String name) throws IOException {
    ClassLoader classLoader = getClass().getClassLoader();
    String path = classLoader.getResource(name).getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    return new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
  }

  @Test
  void fromResponseRSA() throws VCertException, IOException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);
    assertThat(pemCollection.certificate()).isNotNull();
    assertThat(pemCollection.chain()).hasSize(0);
    assertThat(pemCollection.privateKey()).isNotNull();
  }

  @Test
  void fromResponseECDSA() throws VCertException, IOException {
    String body = readResourceAsString("certificates/certWithKeyECDSA.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);
    assertThat(pemCollection.certificate()).isNotNull();
    assertThat(pemCollection.chain()).hasSize(0);
    assertThat(pemCollection.privateKey()).isNotNull();
  }

  @Test
  void keyPasswordRSA() throws VCertException, IOException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);
    PrivateKey privateKey = pemCollection.privateKey();

    PEMCollection pemCollection2 = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, privateKey,
      KEY_PASSWORD);
    String pemPrivateKey = pemCollection2.pemPrivateKey();
    assertThat(pemPrivateKey).contains("BEGIN RSA PRIVATE KEY");
    assertThat(pemPrivateKey).contains("ENCRYPTED");
  }

  @Test
  void keyPasswordECDSA() throws VCertException, IOException {
    String body = readResourceAsString("certificates/certWithKeyECDSA.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);
    PrivateKey privateKey = pemCollection.privateKey();

    PEMCollection pemCollection2 = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, privateKey,
      KEY_PASSWORD);
    String pemPrivateKey = pemCollection2.pemPrivateKey();
    assertThat(pemPrivateKey).contains("BEGIN EC PRIVATE KEY");
    assertThat(pemPrivateKey).contains("ENCRYPTED");
  }
}
