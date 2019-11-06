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

public class TppClient {
  public static void main(String... args) throws VCertException, CertificateEncodingException {
    String tpp_user = System.getenv("TPP_USER");
    String tpp_passwd = System.getenv("TPP_PASSWORD");
    String url = System.getenv("VENAFI_URL");
    String zone = System.getenv("VENAFI_ZONE");

    if (tpp_user == null)
      tpp_user = "local:admin";
    if (tpp_passwd == null)
      tpp_passwd = "Passw0rd";
    if (url == null)
      url = "https://tpp.venafi.example/vedsdk";
    if (zone == null)
      zone = "Default";

    final Config config = Config.builder().connectorType(ConnectorType.TPP).baseUrl(url).build();

    final VCertClient client = new VCertClient(config);

    final Authentication auth =
        Authentication.builder().user(tpp_user).password(tpp_passwd).build();

    client.authenticate(auth);

    final ZoneConfiguration zoneConfiguration = client.readZoneConfiguration(zone);

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
    String newCertId = client.requestCertificate(certificateRequest, zone);

    // Retrieve PEM collection from Venafi
    final CertificateRequest pickupRequest = new CertificateRequest().pickupId(newCertId);
    PEMCollection pemCollection = client.retrieveCertificate(pickupRequest);
    System.out.println(pemCollection.certificate());
  }
}
