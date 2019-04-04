package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.VCertException;
import lombok.Data;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

@Data
public class PEMCollection {
    private Certificate certificate;
    private PrivateKey privateKey;
    private List<Certificate> chain = new ArrayList<>();

    public static PEMCollection fromResponse(String body, ChainOption chainOption) throws VCertException {
        List<Certificate> chain = new ArrayList<>();
        PrivateKey privateKey = null;

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

    // TODO deal with password? is it required?
    public static PEMCollection newPemCollection(Certificate certificate, PrivateKey privateKey, byte[] privateKeyPassword) {
        PEMCollection pemCollection = new PEMCollection();
        pemCollection.certificate(certificate);
        if(privateKey != null) {
            pemCollection.privateKey(privateKey);
        }
        return pemCollection;
    }
}
