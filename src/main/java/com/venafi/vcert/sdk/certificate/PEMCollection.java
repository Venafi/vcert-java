package com.venafi.vcert.sdk.certificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import lombok.Data;
import com.venafi.vcert.sdk.VCertException;


@Data
public class PEMCollection {
  // We don't use AES-256-CBC. Default JDK installations are limited
  // to 128-bit keys, but when AES-256-CBC is specified as algorithm
  // then BouncyCastle will automatically use a 256-bit key size,
  // resulting in an "illegal key size" exception.
  // https://deveshsharmablogs.wordpress.com/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/
  public static final String BOUNCY_CASTLE_ENCRYPTION_ALGORITHM = "AES-128-CBC";
  public static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
  public static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF-OpenSSL";
  public static final String SECRET_KEY_ALGORITHM = "AES";
  // We don't use AES with 256-bit key: see comment for
  // BOUNCY_CASTLE_ENCRYPTION_ALGORITHM.
  public static final int SECRET_KEY_LENGTH_BITS = 128;

  private X509Certificate certificate;
  private PrivateKey privateKey;
  private String privateKeyPassword;
  private List<X509Certificate> chain = new ArrayList<>();

  public static PEMCollection fromResponse(String body, ChainOption chainOption,
      PrivateKey privateKey, String privateKeyPassword) throws VCertException {
    List<X509Certificate> chain = new ArrayList<>();

    PEMParser pemParser = new PEMParser(new StringReader(body));
    JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
    try {
      Object object = pemParser.readObject();
      while (object != null) {
        if (object instanceof X509CertificateHolder) {
          Certificate certificate =
              certificateConverter.getCertificate((X509CertificateHolder) object);
          chain.add((X509Certificate) certificate);
        } else if (object instanceof PEMKeyPair) {
          privateKey = keyConverter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
        }

        object = pemParser.readObject();
      }
    } catch (IOException | CertificateException e) {
      throw new VCertException("Unable to parse certificate from response", e);
    }

    PEMCollection pemCollection;
    if (chain.size() > 0) {
      switch (chainOption) {
        case ChainOptionRootFirst:
          pemCollection = new PEMCollection();
          pemCollection.certificate(chain.get(chain.size() - 1));
          if (chain.size() > 1 && chainOption != ChainOption.ChainOptionIgnore) {
            for (int i = 0; i < chain.size() - 1; i++) {
              pemCollection.chain().add(chain.get(i));
            }
          }
          break;
        default:
          pemCollection = new PEMCollection();
          pemCollection.certificate(chain.get(0));
          if (chain.size() > 1 && chainOption != ChainOption.ChainOptionIgnore) {
            for (int i = 1; i < chain.size(); i++) {
              pemCollection.chain().add(chain.get(i));
            }
          }
          break;
      }
    } else {
      pemCollection = new PEMCollection();
    }
    pemCollection.privateKey(privateKey);
    pemCollection.privateKeyPassword(privateKeyPassword);

    return pemCollection;
  }

  public String pemCertificate() {
    String pem = null;
    if (!Objects.isNull(this.certificate)) {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(outputStream))) {
        pemWriter.writeObject(new PemObject("CERTIFICATE", this.certificate.getEncoded()));
      } catch (CertificateEncodingException e) {
        throw new RuntimeException(e);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      pem = new String(outputStream.toByteArray());
    }
    return pem;
  }

  public String pemPrivateKey() {
    if (Objects.isNull(this.privateKey)) {
      return null;
    }

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(outputStream))) {
      PEMEncryptor encryptor = null;

      if (privateKeyPassword != null) {
        encryptor = new JcePEMEncryptorBuilder(BOUNCY_CASTLE_ENCRYPTION_ALGORITHM)
          .build(privateKeyPassword.toCharArray());
      }

      JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(this.privateKey, encryptor);
      pemWriter.writeObject(gen.generate());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return new String(outputStream.toByteArray());
  }

  public String pemCertificateChain() {
    StringBuilder pem = new StringBuilder();
    if (!Objects.isNull(this.chain)) {
      for (Certificate cert : this.chain) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(outputStream))) {
          pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        } catch (CertificateEncodingException e) {
          throw new RuntimeException(e);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        pem.append(new String(outputStream.toByteArray()));
      }
    }
    return pem.toString();
  }

  public byte[] derCertificate() {
    if (Objects.isNull(this.certificate)) {
      return null;
    }

    try {
      return this.certificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public RawPrivateKey derPrivateKey() {
    if (Objects.isNull(this.privateKey)) {
      return null;
    }

    try {
      RawPrivateKey result = new RawPrivateKey();

      if (KeyType.from(this.privateKey.getAlgorithm()) == KeyType.RSA) {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(this.privateKey.getEncoded());
        ASN1Primitive privateKeyPKCS1ASN1 = pkInfo.parsePrivateKey().toASN1Primitive();
        result.data = privateKeyPKCS1ASN1.getEncoded();
      } else {
        result.data = this.privateKey.getEncoded();
      }

      if (privateKeyPassword == null) {
        return result;
      } else {
        result.iv = new byte[SECRET_KEY_LENGTH_BITS / 8];
        new SecureRandom().nextBytes(result.iv);
        SecretKeySpec secretKey = passwordToCipherSecretKey(privateKeyPassword.toCharArray(), result.iv);
        Cipher c = Cipher.getInstance(CIPHER_TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(result.iv));
        result.data = c.doFinal(result.data);
        return result;
      }
    } catch (IOException | GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public List<byte[]> derCertificateChain() {
    if (Objects.isNull(this.chain)) {
      return null;
    }

    ArrayList<byte[]> result = new ArrayList<>();
    result.ensureCapacity(this.chain.size());
    for (Certificate cert : this.chain) {
      try {
        result.add(cert.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new RuntimeException(e);
      }
    }
    return result;
  }

  public byte[] toPkcs12(String password) throws PKCSException {
    try {
      SubjectKeyIdentifier pubKeyId = new JcaX509ExtensionUtils()
        .createSubjectKeyIdentifier(certificate.getPublicKey());

      OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC)
        .setProvider("BC")
        .build(password.toCharArray());
      ArrayList<PKCS12SafeBag> safeBags = new ArrayList<>();

      safeBags.ensureCapacity(chain.size() + 2);
      safeBags.add(new JcaPKCS12SafeBagBuilder((X509Certificate) certificate)
        .addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId)
        .build());
      for (Certificate intermediateCert: chain) {
        safeBags.add(
          new JcaPKCS12SafeBagBuilder((X509Certificate) intermediateCert)
            .build());
      }
      safeBags.add(new JcaPKCS12SafeBagBuilder(privateKey, encOut)
        .addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId)
        .build());


      PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();
      builder.addEncryptedData(
        new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC)
          .setProvider("BC")
          .build(password.toCharArray()),
        safeBags.toArray(new PKCS12SafeBag[]{}));

      PKCS12PfxPdu pfx = builder.build(
        new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256),
        password.toCharArray());
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(pfx.getEncoded(ASN1Encoding.DL));
      out.close();
      return out.toByteArray();
    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException e) {
      throw new RuntimeException(e);
    }
  }

  public byte[] toJks(String password) throws KeyStoreException, CertificateException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    KeyStore store;

    try {
      store = KeyStore.getInstance(KeyStore.getDefaultType());
      store.load(null, password.toCharArray());
    } catch (KeyStoreException | NoSuchAlgorithmException | IOException e) {
      throw new RuntimeException(e);
    }

    List<X509Certificate> chain = new ArrayList<>();
    chain.add(this.certificate);
    chain.addAll(this.chain);
    store.setKeyEntry("private-key", privateKey, password.toCharArray(),
      chain.toArray(new X509Certificate[] {}));

    try {
      store.store(output, password.toCharArray());
    } catch (NoSuchAlgorithmException | IOException e) {
      throw new RuntimeException(e);
    }

    return output.toByteArray();
  }

  public static SecretKeySpec passwordToCipherSecretKey(char[] password, byte[] iv)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    PBEKeySpec spec = new PBEKeySpec(password, iv, 1, SECRET_KEY_LENGTH_BITS);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
    byte[] key = keyFactory.generateSecret(spec).getEncoded();
    return new SecretKeySpec(key, SECRET_KEY_ALGORITHM);
  }

  @Data
  public static class RawPrivateKey {
    private byte[] iv;
    private byte[] data;

    public boolean isEncrypted() {
      return iv != null;
    }
  }
}
