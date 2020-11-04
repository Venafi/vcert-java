package com.venafi.vcert.sdk.certificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
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

  private Certificate certificate;
  private PrivateKey privateKey;
  private String privateKeyPassword;
  private List<Certificate> chain = new ArrayList<>();

  public static PEMCollection fromResponse(String body, ChainOption chainOption,
      PrivateKey privateKey, String privateKeyPassword) throws VCertException {
    List<Certificate> chain = new ArrayList<>();

    PEMParser pemParser = new PEMParser(new StringReader(body));
    JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
    try {
      Object object = pemParser.readObject();
      while (object != null) {
        if (object instanceof X509CertificateHolder) {
          Certificate certificate =
              certificateConverter.getCertificate((X509CertificateHolder) object);
          chain.add(certificate);
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
}
