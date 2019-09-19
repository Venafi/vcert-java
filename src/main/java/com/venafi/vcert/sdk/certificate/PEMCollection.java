package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.VCertException;
import lombok.Data;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.security.cert.CertificateEncodingException;


@Data
public class PEMCollection {
    private Certificate certificate;
    private PrivateKey privateKey;
    private List<Certificate> chain = new ArrayList<>();

    public static PEMCollection fromResponse(String body, ChainOption chainOption, PrivateKey privateKey) throws VCertException {
        List<Certificate> chain = new ArrayList<>();

        PEMParser pemParser = new PEMParser(new StringReader(body));
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        try {
            Object object = pemParser.readObject();
            while(object != null) {
                if(object instanceof X509CertificateHolder) {
                    Certificate certificate = certificateConverter.getCertificate((X509CertificateHolder) object);
                    chain.add(certificate);
                } else if(object instanceof PEMKeyPair) {
                    privateKey = keyConverter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
                }

                object = pemParser.readObject();
            }
        } catch(IOException | CertificateException e) {
            throw new VCertException("Unable to parse certificate from response", e);
        }

        PEMCollection pemCollection;
        if(chain.size() > 0) {
            switch(chainOption) {
                case ChainOptionRootFirst:
                    pemCollection = newPemCollection(chain.get(chain.size() - 1), null, null);
                    if(chain.size() > 1 && chainOption != ChainOption.ChainOptionIgnore) {
                        for(int i = 0; i < chain.size() - 1; i++) {
                            pemCollection.chain().add(chain.get(i));
                        }
                    }
                    break;
                default:
                    pemCollection = newPemCollection(chain.get(0), null, null);
                    if(chain.size() > 1 && chainOption != ChainOption.ChainOptionIgnore) {
                        for(int i = 1; i < chain.size(); i++) {
                            pemCollection.chain().add(chain.get(i));
                        }
                    }
                    break;
            }
        } else {
            pemCollection = new PEMCollection();
        }
        pemCollection.privateKey(privateKey);

        return pemCollection;
    }

    public static PEMCollection fromResponse(String body, ChainOption chainOption) throws VCertException {
        return fromResponse(body, chainOption, null);
    }

    // TODO deal with password? is it required?
    public static PEMCollection newPemCollection(Certificate certificate, PrivateKey privateKey, byte[] privateKeyPassword) {
        PEMCollection pemCollection = new PEMCollection();
        pemCollection.certificate(certificate);
        if(privateKey != null) {
            pemCollection.privateKey(privateKey);
        }
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
        String pem = null;
        if (!Objects.isNull(this.privateKey)) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            switch(KeyType.from(this.privateKey.getAlgorithm())) {
                case RSA:
                    try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(outputStream))) {   
                        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(this.privateKey.getEncoded());
                        ASN1Encodable privateKeyPKCS1ASN1Encodable = pkInfo.parsePrivateKey();
                        ASN1Primitive privateKeyPKCS1ASN1 = privateKeyPKCS1ASN1Encodable.toASN1Primitive();
                        pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", privateKeyPKCS1ASN1.getEncoded()));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    pem = new String(outputStream.toByteArray());
                    break;
                case ECDSA:
                    try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(outputStream))) {
                        pemWriter.writeObject(new PemObject("EC PRIVATE KEY", this.privateKey.getEncoded())); 
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    pem = new String(outputStream.toByteArray());
                    break;
            }
        }
        return pem;
    }

    public String pemCertificateChain() {
        StringBuilder pem = new StringBuilder();
        if (!Objects.isNull(this.chain)) {
            for(Certificate cert : this.chain) {
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
