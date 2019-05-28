package com.venafi.vcert.sdk.certificate;

import com.google.common.annotations.VisibleForTesting;
import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import lombok.Data;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;
import sun.misc.BASE64Encoder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static java.lang.String.format;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Collections.emptyList;
import static org.apache.commons.lang3.StringUtils.isBlank;

@Data
public class CertificateRequest {
    private PKIXName subject; // TODO change to X500Name
    private Collection<String> dnsNames;
    private Collection<String> emailAddresses;
    private Collection<InetAddress> ipAddresses;
    private Collection<AttributeTypeAndValueSET> attributes;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.UnknownSignatureAlgorithm;
    private String friendlyName;
    private KeyType keyType = KeyType.defaultKeyType();
    private int keyLength;
    private EllipticCurve keyCurve;
    private byte[] csr;
    private KeyPair keyPair;
    private CsrOriginOption csrOrigin = CsrOriginOption.defaultCsrOrigin();
    private String pickupId;
    private ChainOption chainOption;
    private String keyPassword;
    private boolean fetchPrivateKey;
    private String thumbprint;
    private Duration timeout;

    public CertificateRequest() {
        this.dnsNames = emptyList();
        this.emailAddresses = emptyList();
        this.ipAddresses = emptyList();
        this.attributes = emptyList();
    }

    public Duration timeout() {
        return (!Objects.isNull(timeout))
                ?timeout
                :Duration.of(5, MINUTES);
    }

    public ChainOption chainOption() {
        return (!Objects.isNull(chainOption))
                ?chainOption
                :ChainOption.ChainOptionRootFirst;
    }

    public void generatePrivateKey() throws VCertException {
        if(keyPair != null) {
            return;
        }
        switch(keyType) {
            case ECDSA: {
                keyPair = generateECDSAKeyPair(keyCurve);
                break;
            }
            case RSA: {
                if(keyLength == 0) {
                    keyLength = KeyType.defaultRsaLength();
                }
                keyPair = generateRSAKeyPair(keyLength);
                break;
            }
            default:
                throw new VCertException(format("Unable to generate certificate request, key type %s is not supported", keyType.name()));
        }
    }

    public void generateCSR() throws VCertException {
        try {
            PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(
                    signatureAlgorithm.standardName(),
                    subject.toX500Principal(),
                    keyPair.getPublic(),
                    null,
                    keyPair.getPrivate());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            BASE64Encoder base64Encoder = new BASE64Encoder();
            outputStream.write("-----BEGIN CERTIFICATE REQUEST-----".getBytes());
            outputStream.write(System.lineSeparator().getBytes());
            base64Encoder.encodeBuffer(certificationRequest.getEncoded(), outputStream);
            outputStream.write("-----END CERTIFICATE REQUEST-----".getBytes());
            csr = outputStream.toByteArray();
        } catch(Exception e) {
            throw new VCertException("Unable to generate CSR", e);
        }
    }

    @VisibleForTesting
    KeyPair generateECDSAKeyPair(EllipticCurve keyCurve) throws VCertException {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECGenParameterSpec spec = new ECGenParameterSpec(keyCurve.bcName());
            g.initialize(spec);
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new VCertException("No security provider found for KeyFactory.EC", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new VCertException(format("No algorithmn provider for curve %s", keyCurve.bcName()) , e);
        }
    }

    @VisibleForTesting
    KeyPair generateRSAKeyPair(Integer keyLength) throws VCertException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(keyLength);
            return keyPairGenerator.generateKeyPair();
        } catch(NoSuchAlgorithmException e) {
            throw new VCertException("No security provider found for KeyFactory.RSA", e);
        } catch(NoSuchProviderException e) {
            throw new VCertException(format("No algorithm provider for RSA with key length %s", Integer.toString(keyLength)) , e);
        }
    }

    @Data
    public static class PKIXName {

        private static void addAll(X500NameBuilder builder, ASN1ObjectIdentifier identifier, Collection<String> values) {
            if(values != null) {
                values.stream().filter(Objects::nonNull).forEach(value -> builder.addRDN(identifier, value));
            }
        }

        private String commonName;
        private String serialNumber;
        private List<String> country;
        private List<String> organization;
        private List<String> organizationalUnit;
        private List<String> locality;
        private List<String> province;
        private List<String> streetAddress;
        private List<String> postalCode;

        private Collection<AttributeTypeAndValue> names;
        private Collection<AttributeTypeAndValue> extraNames;

        public X500Principal toX500Principal() throws VCertException {
            if(isBlank(commonName)) {
                throw new VCertException("common name must not be null or emtpy");
            }
            X500NameBuilder x500NameBuilder = new X500NameBuilder();
            x500NameBuilder.addRDN(BCStyle.CN, commonName);
            addAll(x500NameBuilder, BCStyle.C, country);
            addAll(x500NameBuilder, BCStyle.O, organization);
            addAll(x500NameBuilder, BCStyle.OU, organizationalUnit);
            addAll(x500NameBuilder, BCStyle.L, locality);
            addAll(x500NameBuilder, BCStyle.ST, province);
            addAll(x500NameBuilder, BCStyle.STREET, streetAddress);
            addAll(x500NameBuilder, BCStyle.POSTAL_CODE, postalCode);

            // todo: serialNumber, names, extraNames

            return new X500Principal(x500NameBuilder.build().toString());
        }
    }

    // Todo do we need this?
    @Data
    public static class AttributeTypeAndValue {
        private Collection<Integer> type;
        private Object value;
    }

    // Todo do we need this?
    @Data
    public static class AttributeTypeAndValueSET {
        private Collection<Integer> type;
        private Collection<Collection<AttributeTypeAndValue>> value;
    }

    public boolean checkCertificate(Certificate certificate) throws VCertException {
        // TODO handle enum exception
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.valueOf(certificate.getPublicKey().getAlgorithm());

        if(keyPair != null && keyPair.getPublic() != null && keyPair.getPrivate() != null) {
            if( keyType.X509Type() != publicKeyAlgorithm) {
                throw new VCertException(format("unmatched key type: %s, %s", keyType.X509Type(), publicKeyAlgorithm.name()));
            }
            switch(publicKeyAlgorithm) {
                case RSA:
                    RSAPublicKey certPublicKey = (RSAPublicKey) certificate.getPublicKey();
                    RSAPublicKey reqPublicKey = (RSAPublicKey) keyPair.getPublic();
                    // TODO can be equals?
                    if(certPublicKey.getModulus().compareTo(reqPublicKey.getModulus()) != 0) {
                        throw new VCertException("unmatched key modules");
                    }
                    break;
                case ECDSA:
                    ECDSAPublicKey certEcdsaPublicKey = (ECDSAPublicKey) certificate.getPublicKey();
                    ECDSAPublicKey reqEcdsaPublicKey = (ECDSAPublicKey) keyPair.getPublic();
                    // TODO make sure comparison is valid
                    if(certEcdsaPublicKey.getPrimeModulusP().compareTo(reqEcdsaPublicKey.getPrimeModulusP()) != 0) {
                        throw new VCertException("unmatched X for eliptic keys");
                    }
                    break;
                default:
                    throw new VCertException(format("unknown key algorithm %s", publicKeyAlgorithm.name()));
            }
        } else if(Objects.nonNull(csr) && csr.length != 0) {
            try {
                PemReader pemReader = new PemReader(new StringReader(new String(csr)));
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemReader.readPemObject().getContent());
                pemReader.close();

                PublicKeyAlgorithm csrPublicKeyAlgorithm = PublicKeyAlgorithm.valueOf(csr.getPublicKey("BC").getAlgorithm());
                if(publicKeyAlgorithm != csrPublicKeyAlgorithm) {
                    throw new VCertException(format("unmatched key type: %s, %s", publicKeyAlgorithm, csrPublicKeyAlgorithm));
                }

                switch(csrPublicKeyAlgorithm) {
                    case RSA:
                        RSAPublicKey certPublicKey = (RSAPublicKey) certificate.getPublicKey();
                        RSAPublicKey reqPublicKey = (RSAPublicKey) csr.getPublicKey();
                        if(certPublicKey.getModulus().compareTo(reqPublicKey.getModulus()) != 0) {
                            throw new VCertException("unmatched key modules");
                        }
                        break;
                    case ECDSA:
                        ECDSAPublicKey certEcdsaPublicKey = (ECDSAPublicKey) certificate.getPublicKey();
                        ECDSAPublicKey reqEcdsaPublicKey = (ECDSAPublicKey) csr.getPublicKey();
                        // TODO make sure comparison is valid
                        if(certEcdsaPublicKey.getPrimeModulusP().compareTo(reqEcdsaPublicKey.getPrimeModulusP()) != 0) {
                            throw new VCertException("unmatched X for eliptic keys");
                        }
                        break;
                }
            } catch(NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException e) {
                throw new VCertException(format("bad csr: %s", e.getMessage()), e);
            }
        }
        return true;
    }
}
