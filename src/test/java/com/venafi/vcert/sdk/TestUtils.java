package com.venafi.vcert.sdk;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class TestUtils {
    private static String loadFileContents(String name) throws IOException {
        ClassLoader classLoader = TestUtils.class.getClassLoader();
        return new String(Files.readAllBytes(Paths.get(classLoader.getResource(name).getPath())));
    }

    public static Certificate loadCertificateFromFile(String name) throws IOException, CertificateException {
        PEMParser pemParser = new PEMParser(new StringReader(loadFileContents("certificates/" + name)));
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        Object object = pemParser.readObject();
        return certificateConverter.getCertificate((X509CertificateHolder) object);
    }

    public static KeyPair loadPrivateKeyFromFileAndGeneratePublicKey(String name) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PEMParser pemParser = new PEMParser(new StringReader(loadFileContents("certificates/" + name)));
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        Object object = pemParser.readObject();
        PrivateKey privateKey = keyConverter.getPrivateKey((PrivateKeyInfo) object);
        RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair loadKeyPairFromFile(String name) throws IOException {
        PEMParser pemParser = new PEMParser(new StringReader(loadFileContents("certificates/" + name)));
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        PEMKeyPair keyPair = (PEMKeyPair) pemParser.readObject();
        PrivateKey privateKey = keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo());
        PublicKey publicKey = keyConverter.getPublicKey(keyPair.getPublicKeyInfo());
        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] getCertificateAsBytes(X509Certificate certificate) throws IOException, CertificateEncodingException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        outputStream.write("-----BEGIN CERTIFICATE-----".getBytes());
        outputStream.write(System.lineSeparator().getBytes());
        outputStream.write(Base64.getEncoder().encode(certificate.getEncoded()));
        outputStream.write("-----END CERTIFICATE-----".getBytes());
        return outputStream.toByteArray();
    }

    public static PKCS10CertificationRequest loadCertificateSigningRequestFromFile(String name) throws IOException {
        StringReader reader = new StringReader(loadFileContents("certificates/" + name));
        try(PEMParser pemParser = new PEMParser(reader)) {
            return (PKCS10CertificationRequest) pemParser.readObject();
        }
    }

    public static Collection<InetAddress> getTestIps() throws SocketException {
        Collection<InetAddress> ips = new ArrayList<>();
        for(NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            for(InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                if(!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                    ips.add(inetAddress);
                }
            }
        }
        return ips;
    }
}
