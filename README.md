# VCert Java

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

VCert is a Java library, SDK, designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

#### Compatibility
VCert releases are tested using the latest version of Trust Protection Platform.  The [latest VCert release](../../releases/latest) should be compatible with Trust Protection Platform 17.3 or higher based on the subset of API methods it consumes.


## Installation

The current version of this library can be installed using Maven:

```
mvn install
```


## Usage

A basic example of creating a certificate using VCert Java:

```
final Config config = Config.builder()
        .connectorType(ConnectorType.TPP)
        .baseUrl("https://tpp.venafi.example/vedsdk")
        .build();
        
/* or for Venafi Cloud
final Config config = Config.builder()
        .connectorType(ConnectorType.CLOUD)
        .build();
*/

final VCertClient client = new VCertClient(config);

final Authentication auth = Authentication.builder()
        .user("local:apiuser")
        .password("password")
        .build();

/* or for Venafi Cloud
final Authentication auth = Authentication.builder()
        .apiKey("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .build();
*/

client.authenticate(auth);

//////////////////////////////////////
///// Local Generated CSR - RSA //////
//////////////////////////////////////

// Generate a key pair and certificate signing request
CertificateRequest certificateRequest = new CertificateRequest().subject(
        new CertificateRequest.PKIXName()
                .commonName("vcert-java.venafi.example")
                .organization(Collections.singletonList("Example Company"))
                .organizationalUnit(Arrays.asList("Example Division"))
                .country(Collections.singletonList("US"))
                .locality(Collections.singletonList("Salt Lake City"))
                .province(Collections.singletonList("Utah")))
        .dnsNames(Arrays.asList("alfa.venafi.example", "bravo.venafi.example", "charlie.venafi.example"))
        .ipAddresses(Arrays.asList(InetAddress.getByName("10.20.30.40"),InetAddress.getByName("172.16.172.16")))
        .emailAddresses(Arrays.asList("larry@venafi.example", "moe@venafi.example", "curly@venafi.example"))
        .keyType(KeyType.RSA);
        
ZoneConfiguration zoneConfiguration = client.readZoneConfiguration("Certificates\\VCert");
certificateRequest = client.generateRequest(zoneConfiguration, certificateRequest);   

// Submit the certificate request
client.requestCertificate(certificateRequest, "Certificates\\VCert");

// Retrieve PEM collection from Venafi
PEMCollection pemCollection = client.retrieveCertificate(certificateRequest);

System.out.println(pemCollection.pemPrivateKey());
System.out.println(pemCollection.pemCertificate());
System.out.println(pemCollection.pemCertificateChain());

/////////////////////////////
///// User Provided CSR /////
/////////////////////////////
        
String csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
        "MIIC8DCCAdgCAQAwgY4xCzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRVdGFoMRcwFQYD\n" +
        "VQQHEw5TYWx0IExha2UgQ2l0eTEYMBYGA1UEChMPRXhhbXBsZSBDb21wYW55MRkw\n" +
        "FwYDVQQLExBFeGFtcGxlIERpdmlzaW9uMSIwIAYDVQQDExl2Y2VydC1qYXZhLnZl\n" +
        "bmFmaS5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9PHk\n" +
        "bR5i0pV6M08XXi+Z0tAJkIU3TLG0Hr0n5tY6JIcP3Sc8wrodgMN66WUP6oLV/yqR\n" +
        "2lKom+dc9dIN9iaVUfnpPwhjyuIMyd0svmU2hnZj3InG5kvqnMnzQvRfWx0OKmMB\n" +
        "c652qZsgR3d6I+YufhIsuMxkWMev2njXGZAnThGVMv/iD9dLTO+0lTwwSbvM1lxw\n" +
        "YxAwdVFX1+vl0ORyOs4OUqUFv3i6qvS/U/RI45TrgR+XA2/8xPlo5gfGrnFfiyJJ\n" +
        "jMctOak2mOVrR/2kXYcOw+37zkpJEADSZBgm/YzqdYtrI8t/M4uClkn9WQgTijC1\n" +
        "eN4hFKyTGeOGIqKI/QIDAQABoBwwGgYJKoZIhvcNAQkOMQ0wCzAJBgNVHRMEAjAA\n" +
        "MA0GCSqGSIb3DQEBCwUAA4IBAQDOxsP3fFsx/UOLudVm6MAuAFZfZxm7P1sZrYhb\n" +
        "tgshSXDlruiO7/ovb8rDrRrKJjAx4+tXlQRsDfxIpvuNcAd7//WCjjIfAoNlGRW4\n" +
        "cMtWfvCN1p7XsVer+JJHtM5UZ+oKS06hdPppDP4rfjyhTM5Y0M8JAgMcGsm7lrWU\n" +
        "w1ly6k8k5NzadWGOZwvz75qrn0ufHuI96sPsL5wmqty34BfnBy4iMddU3m/Y1qQb\n" +
        "VfKV2CRWybwV/QeCtogXvI7Nou2LZQDWI57498Nzif1Zvfy0/ab8XBkX2vMUXcnm\n" +
        "1A7/9ezwgYTZvy1rbBSKBSjAx/MAOPUM93OcjT6tKtEeEnI8\n" +
        "-----END CERTIFICATE REQUEST-----";

certificateRequest = new CertificateRequest().csr(csr.getBytes())
        .csrOrigin(com.venafi.vcert.sdk.certificate.CsrOriginOption.UserProvidedCSR)
        .dnsNames(Arrays.asList("alfa.venafi.example", "bravo.venafi.example", "charlie.venafi.example"))
        .ipAddresses(Arrays.asList(InetAddress.getByName("10.20.30.40"),InetAddress.getByName("172.16.172.16")))
        .emailAddresses(Arrays.asList("larry@venafi.example", "moe@venafi.example", "curly@venafi.example"));

// Submit the certificate request
client.requestCertificate(certificateRequest, "Certificates\\VCert");

// Retrieve PEM collection from Venafi
pemCollection = client.retrieveCertificate(certificateRequest);

System.out.println(pemCollection.pemCertificate());
System.out.println(pemCollection.pemCertificateChain());

```

## Prerequisites for using with Trust Protection Platform

1. A user account that has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write, Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

The requirement for the CA Template to be assigned by policy follows a long standing Venafi best practice which also met our design objective to keep the certificate request process simple for VCert users. If you require the ability to specify the CA Template with the request you can use the TPP REST APIs but please be advised this goes against Venafi recommendations.

## Acceptance Tests

To run the acceptance tests the following environment variables must be set:

| NAME | NOTES |
|------|-------|
| VENAFI_USER | Only for TPP connector tests |
| VENAFI_PASSWORD | Only for TPP connector tests |
| VENAFI_TPP_URL | Only for TPP connector tests |
| VENAFI_API_KEY | Taken from account after logged into TPP |
| VENAFI_CERT_COMMON_NAME | Used for cert creation, should match configured domains |
| VENAFI_CLOUD_URL | Only for cloud connector tests |
| VENAFI_ZONE | Policy folder for TPP |

Acceptance test  are executed with:
```
mvn "-Dtest=*AT" test
```


## Contributing to VCert

1. Fork it to your account (https://github.com/Venafi/vcert-java/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert-java.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert-java/pull/new/your-branch-name)


## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
