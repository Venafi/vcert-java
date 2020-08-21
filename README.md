![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# VCert Java

VCert is a Java library, SDK, designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

#### Compatibility

VCert releases are tested using the latest version of Trust Protection Platform and Venafi Cloud.
The [latest VCert release](../../releases/latest) should be compatible with Trust Protection
Platform 17.3 or higher based on the subset of API methods it consumes.  Token Authentication
requires 19.2 or higher; for earlier versions, username/password authentication (deprecated) applies.

## Installation

The current version of this library can be installed using Maven:

```sh
mvn install
```

## Usage

Instantiate a client for Trust Protection Platform using token authentication with an existing
access token:

```sh
final Authentication auth = Authentication.builder()
        .accessToken("9PQwQeiTLhcB8/W3/z2Lbw==")
        .build();

final Config config = Config.builder()
        .connectorType(ConnectorType.TPP_TOKEN)
        .baseUrl("https://tpp.venafi.example")
        .credentials(auth)
        .build();

final VCertTknClient client = new VCertTknClient(config);
```

Or instantiate a client for Venafi Cloud:

```sh
final Authentication auth = Authentication.builder()
        .apiKey("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .build();

final Config config = Config.builder()
        .connectorType(ConnectorType.CLOUD)
        .build();

final VCertClient client = new VCertClient(config);
client.authenticate(auth);
```

Then use your client to request certificates:

```sh
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
client.requestCertificate(certificateRequest, zoneConfiguration);

// Retrieve PEM collection from Venafi
pemCollection = client.retrieveCertificate(certificateRequest);

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
client.requestCertificate(certificateRequest, zoneConfiguration);

// Retrieve PEM collection from Venafi
pemCollection = client.retrieveCertificate(certificateRequest);

System.out.println(pemCollection.pemCertificate());
System.out.println(pemCollection.pemCertificateChain());
```

You can also instantiate a client for Trust Protection Platform using token authentication
_without_ an existing token by providing a username/password.  Such a token is generally for
short-term or temporary use and as such should be revoked upon completion of your tasks:

```sh
final Authentication auth = Authentication.builder()
        .user("local:apiuser")
        .password("password")
        .build();

final Config config = Config.builder()
        .connectorType(ConnectorType.TPP_TOKEN)
        .baseUrl("https://tpp.venafi.example")
        .build();

final VCertTknClient client = new VCertTknClient(config);
client.getAccessToken(auth);

///// REQUEST, RENEW, AND/OR REVOKE CERTIFICATES...

client.revokeAccessToken();
```

:thumbsdown: To instantiate a client for Trust Protection Platform using deprecated username/password
authentication:

```sh
final Authentication auth = Authentication.builder()
        .user("local:apiuser")
        .password("password")
        .build();

final Config config = Config.builder()
        .connectorType(ConnectorType.TPP)
        .baseUrl("https://tpp.venafi.example/vedsdk")
        .build();

final VCertClient client = new VCertClient(config);
client.authenticate(auth);
```

## Prerequisites for using with Trust Protection Platform

1. A user account that has an authentication token with "certificate:manage,revoke" scope (i.e.
access to the "Venafi VCert SDK" API Application as of 20.1) or has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write,
Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is
service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

The requirement for the CA Template to be assigned by policy follows a long standing Venafi best
practice which also met our design objective to keep the certificate request process simple for
VCert users. If you require the ability to specify the CA Template with the request you can use the
TPP REST APIs but please be advised this goes against Venafi recommendations.

## Prerequisites for using with Venafi Cloud

1. The Venafi Cloud REST API is accessible at https://api.venafi.cloud from the system where VCert
will be executed.
2. You have successfully registered for a Venafi Cloud account, have been granted at least the
"DevOps" role, and know your API key.
3. A CA Account and Issuing Template exist and have been configured with:
    1. Recommended Settings values for:
        1. Organizational Unit (OU)
        2. Organization (O)
        3. City/Locality (L)
        4. State/Province (ST)
        5. Country (C)
    2. Issuing Rules that:
        1. (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        2. (Recommended) Restricts the Key Length to 2048 or higher
        3. (Recommended) Does not allow Private Key Reuse
4. A DevOps Project exists to which you have been granted access.
5. A Zone has exists within the Project that uses the Issuing Template, and you know the Zone ID.

## Acceptance Tests

To run the acceptance tests the following environment variables must be set:

| NAME | NOTES |
|------|-------|
| TPPURL | Only for TPP connector tests (e.g. https://tpp.venafi.example/vedsdk) |
| TPP_TOKEN_URL | Only for TPP connector tests involving token auth (e.g. https://tpp.venafi.example) |
| TPPUSER | Only for TPP connector tests |
| TPPPASSWORD | Only for TPP connector tests |
| TPPZONE | Policy folder for TPP |
| CLOUDURL | Only for Venafi Cloud tests running against non-production environments (uncommon) |
| APIKEY | Obtained by logging into Venafi Cloud after registering |
| CLOUDZONE | Zone ID or ProjectName\ZoneName for Venafi Cloud |

Acceptance test  are executed with:

```sh
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
