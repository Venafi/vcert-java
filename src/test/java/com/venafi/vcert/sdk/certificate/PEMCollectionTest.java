package com.venafi.vcert.sdk.certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.junit.jupiter.api.Test;
import com.venafi.vcert.sdk.VCertException;

class PEMCollectionTest {
  private static final String KEY_PASSWORD = "newPassw0rd!";
  private static final String PKCS12_PASSWORD = "abcd";

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
  void fromResponseEncryptedKey() throws VCertException, IOException {
    String body = readResourceAsString("certificates/certWithEncryptedKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore,
      null, KEY_PASSWORD);
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

  @Test
  void derCertificate() throws VCertException, IOException, CertificateException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);

    byte[] derData = pemCollection.derCertificate();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derData));
    assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=test@test.com");
  }

  @Test
  void derCertificateChain() throws VCertException, IOException, CertificateException {
    String body = readResourceAsString("certificates/certWithChainAndKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionRootLast, null, null);

    List<byte[]> derChain = pemCollection.derCertificateChain();
    assertThat(derChain.size()).isEqualTo(2);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derChain.get(0)));
    assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=Dedicated - Venafi Cloud Built-In Intermediate CA - G1,OU=Built-in,O=Venafi\\, Inc.,C=US");
  }

  @Test
  void derPrivateKeyWithoutPassword() throws VCertException, IOException, GeneralSecurityException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);

    PEMCollection.RawPrivateKey privKey = pemCollection.derPrivateKey();
    assertThat(privKey.isEncrypted()).isFalse();
    assertThatCode(() -> {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKey.data());
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      keyFactory.generatePrivate(keySpec);
    }).doesNotThrowAnyException();
  }

  @Test
  void derPrivateKeyWithPassword() throws VCertException, IOException, GeneralSecurityException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null,
      KEY_PASSWORD);

    PEMCollection.RawPrivateKey privKey = pemCollection.derPrivateKey();
    assertThat(privKey.isEncrypted()).isTrue();
    assertThatExceptionOfType(InvalidKeySpecException.class).isThrownBy(() -> {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKey.data());
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      keyFactory.generatePrivate(keySpec);
    });

    byte[] decryptedPrivKey;
    SecretKeySpec secretKey = PEMCollection.passwordToCipherSecretKey(
      KEY_PASSWORD.toCharArray(), privKey.iv());
    Cipher c = Cipher.getInstance(PEMCollection.CIPHER_TRANSFORMATION);
    c.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(privKey.iv()));
    decryptedPrivKey = c.doFinal(privKey.data());

    assertThatCode(() -> {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedPrivKey);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      keyFactory.generatePrivate(keySpec);
    }).doesNotThrowAnyException();
  }

  @Test
  void toPkcs12() throws VCertException, IOException, GeneralSecurityException, PKCSException {
    String body = readResourceAsString("certificates/certWithKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore, null, null);

    byte[] pkcs12Data = pemCollection.toPkcs12(PKCS12_PASSWORD);

    PKCS12PfxPdu pfx = new PKCS12PfxPdu(pkcs12Data);
    assertThat(
      pfx.isMacValid(
        new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE),
        PKCS12_PASSWORD.toCharArray()
      )
    ).isTrue();

    ContentInfo[] infos = pfx.getContentInfos();
    assertThat(infos.length).isEqualTo(1);
    assertThat(infos[0].getContentType()).isEqualTo(PKCSObjectIdentifiers.encryptedData);
  }

  @Test
  void toJks() throws VCertException, IOException, GeneralSecurityException {
    String body = readResourceAsString("certificates/certWithChainAndKey.pem");
    PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionRootLast, null, null);

    byte[] jksData = pemCollection.toJks(KEY_PASSWORD);

    KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
    store.load(new ByteArrayInputStream(jksData), KEY_PASSWORD.toCharArray());
    ArrayList<String> aliases = Collections.list(store.aliases());
    assertThat(aliases.size()).isEqualTo(1);
    assertThat(aliases.get(0)).isEqualTo("private-key");

    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) store.getEntry("private-key",
      new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray()));
    assertThat(entry.getPrivateKey().getEncoded()).isEqualTo(
      pemCollection.privateKey().getEncoded());
    assertThat(entry.getCertificate().getEncoded()).isEqualTo(
      pemCollection.certificate().getEncoded());
    assertThat(entry.getCertificateChain().length).isEqualTo(
      pemCollection.chain().size() + 1);
  }
}
