package com.venafi.vcert.sdk.certificate;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.platform.commons.util.StringUtils.isNotBlank;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;

class CertificateRequestTest {

  @Test
  void generateECDSAPrivateKey() {
    Security.addProvider(new BouncyCastleProvider());

    assertThatCode(() -> {
      CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());
      KeyPair keyPair = certificateRequest.generateECDSAKeyPair(EllipticCurve.EllipticCurveP224);
      verifyKeyPair(keyPair, SignatureAlgorithm.ECDSAWithSHA256.standardName());
    }).doesNotThrowAnyException();
  }

  @Test
  void generateRSAKeyPair() {
    assertThatCode(() -> {
      CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());
      KeyPair keyPair = certificateRequest.generateRSAKeyPair(512);
      verifyKeyPair(keyPair, SignatureAlgorithm.SHA256WithRSA.standardName());
    }).doesNotThrowAnyException();
  }

  @Test
  void generateCertificateRequestWithRSAKey() throws IOException, VCertException {
    Security.addProvider(new BouncyCastleProvider());

    CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());

    certificateRequest.keyType(KeyType.RSA);
    certificateRequest.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);

    certificateRequest.generatePrivateKey();
    certificateRequest.generateCSR();

    PKCS10CertificationRequest cert = getCertRequest(certificateRequest);

    String subject = cert.getSubject().toString();
    assertThat(subject).contains("CN=vcert.test.vfidev.com");
    assertThat(subject).contains("O=Venafi\\, Inc.");
    assertThat(subject).contains("OU=Engineering");
    assertThat(subject).contains("OU=Automated Tests");
    assertThat(subject).contains("C=US");
    assertThat(subject).contains("L=SLC");
    assertThat(subject).contains("ST=Utah");

    // TODO verify certificate is valid
  }

  @Test
  void generateCertificateRequestWithECDSAKey() throws VCertException, IOException {
    Security.addProvider(new BouncyCastleProvider());

    CertificateRequest certificateRequest = generateTestCertificateRequest(getTestIps());

    certificateRequest.keyType(KeyType.ECDSA);
    certificateRequest.keyCurve(EllipticCurve.EllipticCurveP256);
    certificateRequest.signatureAlgorithm(SignatureAlgorithm.ECDSAWithSHA256);

    certificateRequest.generatePrivateKey();
    certificateRequest.generateCSR();

    PKCS10CertificationRequest cert = getCertRequest(certificateRequest);

    String subject = cert.getSubject().toString();
    assertThat(subject).contains("CN=vcert.test.vfidev.com");
    assertThat(subject).contains("O=Venafi\\, Inc.");
    assertThat(subject).contains("OU=Engineering");
    assertThat(subject).contains("OU=Automated Tests");
    assertThat(subject).contains("C=US");
    assertThat(subject).contains("L=SLC");
    assertThat(subject).contains("ST=Utah");

    // TODO verify certificate is valid

  }

  // TODO rework
  @ParameterizedTest
  @MethodSource("provideCertificatedForCheckCertificate")
  void checkCertificate(CertificateRequest certificateRequest, Certificate certificate,
      boolean isValid, String errorMessage) {
    Security.addProvider(new BouncyCastleProvider());

    boolean validCert;
    try {
      validCert = certificateRequest.checkCertificate(certificate);
      if (!isValid && validCert) {
        fail("certificate should failed but check returns that its valid");
      }
      assertThat(validCert).isTrue();
    } catch (VCertException e) {
      if (isValid) {
        if (isNotBlank(errorMessage) && !e.getMessage().contains(errorMessage)) {
          fail(format("unexpected error '%s' (should conatins %s)", e.getMessage(), errorMessage));
        } else {
          fail(format("cert should be valid but checker found error: %s", e.getMessage()));
        }
      }
    }

  }

  private static Stream<Arguments> provideCertificatedForCheckCertificate()
      throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
    KeyPair rsaKeyInvalid = loadKeyPairFromFile("checkCertificatePrivateKeyRSAinvalid");
    KeyPair rsaKeyValid = loadKeyPairFromFile("checkCertificatePrivateKeyRSAvalid");

    return Stream.of(
        Arguments.of(createCertFor(KeyType.RSA, rsaKeyValid),
            loadCertificateFromFile("checkCertificateRSACert"), true, ""),
        Arguments.of(createCertFor(KeyType.ECDSA, rsaKeyValid),
            loadCertificateFromFile("checkCertificateRSACert"), false, "key type"),
        Arguments.of(createCertFor(KeyType.RSA, rsaKeyInvalid),
            loadCertificateFromFile("checkCertificateRSACert"), false, "key modules"),
        Arguments.of(
            createCertSigningRequestFor(
                loadCertificateSigningRequestFromFile("checkCertificateCSRRSA")),
            loadCertificateFromFile("checkCertificateRSACert"), true, ""),
        Arguments.of(
            createCertSigningRequestFor(
                loadCertificateSigningRequestFromFile("checkCertificateCSRRSA")),
            loadCertificateFromFile("checkCertificateRSACert2"), false, "key modules"));
  }

  private static CertificateRequest createCertFor(KeyType keyType, KeyPair keyPair) {
    return new CertificateRequest().keyType(keyType).keyPair(keyPair);
  }

  private static CertificateRequest createCertSigningRequestFor(
      PKCS10CertificationRequest certSigningReq) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write("-----BEGIN CERTIFICATE REQUEST-----".getBytes());
    outputStream.write(System.lineSeparator().getBytes());
    outputStream.write(Base64.getEncoder().encode(certSigningReq.getEncoded()));
    outputStream.write(System.lineSeparator().getBytes());
    outputStream.write("-----END CERTIFICATE REQUEST-----".getBytes());
    return new CertificateRequest().csr(outputStream.toByteArray());
  }

  private static KeyPair loadKeyPairFromFile(String name)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    ClassLoader classLoader = CertificateRequestTest.class.getClassLoader();
    String path = classLoader.getResource("certificates/" + name).getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    String body = new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
    PEMParser pemParser = new PEMParser(new StringReader(body));
    JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
    Object object = pemParser.readObject();
    pemParser.close();
    PrivateKey privateKey = keyConverter.getPrivateKey((PrivateKeyInfo) object);
    RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
    RSAPublicKeySpec publicKeySpec =
        new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  private static Certificate loadCertificateFromFile(String name)
      throws IOException, CertificateException {
    ClassLoader classLoader = CertificateRequestTest.class.getClassLoader();
    String path = classLoader.getResource("certificates/" + name).getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    String body = new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
    PEMParser pemParser = new PEMParser(new StringReader(body));
    JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    Object object = pemParser.readObject();
    pemParser.close();
    return certificateConverter.getCertificate((X509CertificateHolder) object);
  }

  private static PKCS10CertificationRequest loadCertificateSigningRequestFromFile(String name)
      throws IOException {
    ClassLoader classLoader = CertificateRequestTest.class.getClassLoader();
    String path = classLoader.getResource("certificates/" + name).getPath();
    // windows platform: if it starts with /C: then remove the leading slash
    if (path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    String body = new String(Files.readAllBytes(Paths.get(path).toAbsolutePath()));
    StringReader reader = new StringReader(body);
    try (PEMParser pemParser = new PEMParser(reader)) {
      return (PKCS10CertificationRequest) pemParser.readObject();
    }
  }

  private PKCS10CertificationRequest getCertRequest(CertificateRequest certificateRequest)
      throws IOException {
    StringReader reader = new StringReader(new String(certificateRequest.csr()));
    try (PEMParser pemParser = new PEMParser(reader)) {
      return (PKCS10CertificationRequest) pemParser.readObject();
    }
  }

  private CertificateRequest generateTestCertificateRequest(Collection<InetAddress> ips)
      throws UnknownHostException {
    return new CertificateRequest()
        .subject(new CertificateRequest.PKIXName().commonName("vcert.test.vfidev.com")
            .organization(Collections.singletonList("Venafi, Inc."))
            .organizationalUnit(Arrays.asList("Engineering", "Automated Tests"))
            .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
            .province(Collections.singletonList("Utah")))
        .dnsNames(Collections.singletonList(InetAddress.getLocalHost().getHostName()))
        .ipAddresses(ips);
  }

  private Collection<InetAddress> getTestIps() throws SocketException {
    Collection<InetAddress> ips = new ArrayList<>();
    for (NetworkInterface networkInterface : Collections
        .list(NetworkInterface.getNetworkInterfaces())) {
      for (InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
        if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
          ips.add(inetAddress);
        }
      }
    }
    return ips;
  }

  private void verifyKeyPair(KeyPair keyPair, String signatureName) throws Exception {
    byte[] challenge = new byte[10000];
    ThreadLocalRandom.current().nextBytes(challenge);

    Signature sig = Signature.getInstance(signatureName, "BC");
    sig.initSign(keyPair.getPrivate());
    sig.update(challenge);
    byte[] signature = sig.sign();

    sig.initVerify(keyPair.getPublic());
    sig.update(challenge);

    assertThat(sig.verify(signature)).isTrue();
  }
}
