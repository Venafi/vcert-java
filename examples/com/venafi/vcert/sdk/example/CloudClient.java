package com.venafi.vcert.sdk.example;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Collections;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.VCertClient;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

public class CloudClient {
  public static void main(String[] args) throws VCertException, CertificateEncodingException,
      NoSuchAlgorithmException, KeyManagementException {
    String url = System.getenv("CLOUDURL");
    String zone = System.getenv("CLOUDZONE");
    String productNameAndVersion = System.getenv("PRODUCT");
    String apiKey = System.getenv("APIKEY");

    url = "https://api.dev01.qa.venafi.io";
    
    if (zone == null) {
      zone = "My Project\\My Zone";
//      zone = "38992cc0-0177-11ea-a3f0-2b5db8116980";
    }
    if (productNameAndVersion == null)
      productNameAndVersion = "My Application 1.0.0.0";
    if (apiKey == null)
      apiKey = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    apiKey = "b951a227-3c84-41ff-b6db-93b6f4476192";
    
    Config config = Config.builder().connectorType(ConnectorType.CLOUD).baseUrl(url)
        .productNameAndVersion(productNameAndVersion)
        // To use proxy uncomment the lines below
         .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8888)))
         .proxyUser("myUser")
         .proxyPassword("myPasscode")
        .build();

    Authentication auth = Authentication.builder().apiKey(apiKey).build();

    VCertClient client = new VCertClient(config);
    client.authenticate(auth);

    ZoneConfiguration zoneConfiguration = client.readZoneConfiguration(zone);

    // Generate a certificate
    CertificateRequest certificateRequest = new CertificateRequest()
        .subject(new CertificateRequest.PKIXName().commonName("vcert-java.venafi.example")
            .organization(Collections.singletonList("Venafi, Inc."))
            .organizationalUnit(Arrays.asList("Product Management"))
            .country(Collections.singletonList("US"))
            .locality(Collections.singletonList("Salt Lake City"))
            .province(Collections.singletonList("Utah")))
        .keyType(KeyType.RSA).keyLength(2048);

    certificateRequest = client.generateRequest(zoneConfiguration, certificateRequest);

    // Submit the certificate request
    client.requestCertificate(certificateRequest, zoneConfiguration);

    // Retrieve PEM collection from Venafi
    PEMCollection pemCollection = client.retrieveCertificate(certificateRequest);
    System.out.println(pemCollection.certificate());
  }
}
