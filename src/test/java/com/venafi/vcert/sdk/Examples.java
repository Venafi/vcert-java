package com.venafi.vcert.sdk;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import org.apache.commons.codec.digest.DigestUtils;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

public class Examples {

  public static void main(String... args) throws VCertException, CertificateEncodingException {
    final Config config =
        Config.builder().connectorType(ConnectorType.CLOUD).zone("Default").build();

    final VCertClient client = new VCertClient(config);

    final Authentication auth =
        Authentication.builder().apiKey("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").build();

    client.authenticate(auth);
    final ZoneConfiguration zoneConfiguration = client.readZoneConfiguration("My Project\\My Zone");

    // Generate a certificate
    CertificateRequest certificateRequest = new CertificateRequest()
        .subject(new CertificateRequest.PKIXName().commonName("cert.test")
            .organization(Collections.singletonList("Venafi, Inc."))
            .organizationalUnit(Arrays.asList("Engineering"))
            .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
            .province(Collections.singletonList("Utah")))

        .keyType(KeyType.RSA);
    certificateRequest = client.generateRequest(zoneConfiguration, certificateRequest);

    // Submit the certificate request
    String newCertId = client.requestCertificate(certificateRequest, zoneConfiguration);

    // Retrieve PEM collection from Venafi
    final CertificateRequest pickupRequest = new CertificateRequest().pickupId(newCertId);
    PEMCollection pemCollection = client.retrieveCertificate(pickupRequest);
    System.out.println(pemCollection.certificate());

    // Renew the certificate
    X509Certificate cert = (X509Certificate) pemCollection.certificate();
    String thumbprint = DigestUtils.sha1Hex(cert.getEncoded()).toUpperCase();
    final CertificateRequest certificateRequestToRenew =
        new CertificateRequest().subject(new CertificateRequest.PKIXName().commonName("cert.test")
            .organization(Collections.singletonList("Venafi, Inc."))
            .organizationalUnit(Arrays.asList("Engineering"))
            .country(Collections.singletonList("US")).locality(Collections.singletonList("SLC"))
            .province(Collections.singletonList("Utah")));

    client.generateRequest(zoneConfiguration, certificateRequestToRenew);

    final RenewalRequest renewalRequest =
        new RenewalRequest().thumbprint(thumbprint).request(certificateRequestToRenew);
    final String renewedCertificate = client.renewCertificate(renewalRequest);

    // Retrieve PEM collection from Venafi
    final CertificateRequest renewPickupRequest =
        new CertificateRequest().pickupId(renewedCertificate);
    PEMCollection pemCollectionRenewed = client.retrieveCertificate(pickupRequest);
    System.out.println(pemCollectionRenewed.certificate());

  }

}
