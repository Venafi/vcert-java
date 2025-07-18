[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
:warning: _**This community-supported open source project has reached its END-OF-LIFE, and as of June 5th 2025, this project is deprecated and will no longer be maintained**._

# VCert Java

VCert is a Java library, SDK, designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi as a Service](https://www.venafi.com/venaficloud).

#### Compatibility

VCert releases are tested using the latest version of Trust Protection Platform and Venafi as a Service.
The [latest VCert release](../../releases/latest) should be compatible with Trust Protection
Platform 17.3 or higher based on the subset of API methods it consumes.  Token Authentication
requires 19.2 or higher; for earlier versions, username/password authentication (deprecated) applies.

## Installation

VCert-Java releases are published to the [Maven Central Repository](https://search.maven.org/)
making them easy to use with Java projects built using popular tools.  To build using Maven, start
by identifying the version number of the 
[latest release in the Maven Central Repository](https://search.maven.org/search?q=a:vcert-java).
Then add the following dependency configuration to your Java project's `pom.xml`, replacing "0.0.1"
with the appropriate version:
```
<dependency>
  <groupId>io.github.venafi</groupId>
  <artifactId>vcert-java</artifactId>
  <version>0.0.1</version>
</dependency>
```

Config snippets for building using other tools are listed on the release page in the Maven Central
Respository.  For example, [this page](https://search.maven.org/artifact/io.github.venafi/vcert-java/0.6.2/jar)
shows snippets for VCert-Java v0.6.2.

## Usage


Instantiate a client for Trust Protection Platform using token authentication with an existing
access token:

```java
//Create an Authentication object with the access token
final Authentication auth = Authentication.builder()
        .accessToken("9PQwQeiTLhcB8/W3/z2Lbw==")
        .build();

//Create a Config object setting the Authentication object
final Config config = Config.builder()
        .connectorType(ConnectorType.TPP_TOKEN)
        .baseUrl("https://tpp.venafi.example")
        .credentials(auth)
        .build();

//Create the client with the Config object. The client will be authenticated
final VCertTknClient client = new VCertTknClient(config);
```

Or instantiate a client for Venafi as a Service:

```java
//Create an Authentication object with the API Key
final Authentication auth = Authentication.builder()
        .apiKey("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .build();

//Create a Config object setting the Authentication object
final Config config = Config.builder()
        .connectorType(ConnectorType.CLOUD)
        .credentials(auth)
        .build();

//Create the client with the Config object. The client will be authenticated
final VCertClient client = new VCertClient(config);
```

Or instantiate a client for Venafi as a Service EU:

```java
//Create an Authentication object with the API Key
final Authentication auth = Authentication.builder()
        .apiKey("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .build();

//Create a Config object setting the Authentication object
final Config config = Config.builder()
        .connectorType(ConnectorType.CLOUD)
        .baseUrl("https://api.venafi.eu")
        .credentials(auth)
        .build();

//Create the client with the Config object. The client will be authenticated
final VCertClient client = new VCertClient(config);
```

Then use your client to request certificates:
- For Trust Protection Platform, the `zone` format is the DN of a policy with or without the "\VED\Policy\" prefix (e.g. "\VED\Policy\Certificates\VCert" or simply "Certificates\VCert")
- For Venafi as a Service, the `zone` format is the name of an OutagePREDICT Application and the API Alias of an Issuing Template assigned to it delimited by a single backslash character (e.g. "My Application\My CIT")

```java
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

To specify the desired validity when requesting a certificate from Trust Protection Platform
or Venafi as a Service, use `validityHours()`:

```java
CertificateRequest certificateRequest = new CertificateRequest().subject(
        new CertificateRequest.PKIXName()
                .commonName("vcert-java.venafi.example"))
        .dnsNames(Arrays.asList("alfa.venafi.example", "bravo.venafi.example", "charlie.venafi.example"))
        .keyType(KeyType.RSA)
        .validityHours(720)
        .issuerHint("MICROSOFT"); // needed for TPP when the CA is "DIGICERT", "ENTRUST", or "MICROSOFT"
```

To assign Custom Field values when requesting a certificate from Trust Protection Platform,
construct a list of CustomField objects (name/value) and then add them to the request using
`customFields()`:

```java
List<CustomField> fields = new ArrayList<CustomField>();
fields.add(new CustomField("Cost Center", "ABC123"));
fields.add(new CustomField("Environment", "Production"));
fields.add(new CustomField("Environment", "Staging"));

CertificateRequest certificateRequest = new CertificateRequest().subject(
        new CertificateRequest.PKIXName()
                .commonName("vcert-java.venafi.example"))
        .dnsNames(Arrays.asList("alfa.venafi.example", "bravo.venafi.example", "charlie.venafi.example"))
        .keyType(KeyType.RSA)
        .customFields(fields);
```

You can also instantiate a client for Trust Protection Platform using token authentication
_without_ an existing token by providing a username/password.  Such a token is generally for
short-term or temporary use and as such should be revoked upon completion of your tasks:

```java
//Create an Authentication object with the user and password
final Authentication auth = Authentication.builder()
        .user("local:apiuser")
        .password("password")
        .build();

//Create a Config object
final Config config = Config.builder()
        .connectorType(ConnectorType.TPP_TOKEN)
        .baseUrl("https://tpp.venafi.example")
        .build();
        
//Create the client with the Config object. The client is not authenticated yet
final VCertTknClient client = new VCertTknClient(config);

//Get the access token. It will cause the client's authentication
client.getAccessToken(auth);

///// REQUEST, RENEW, AND/OR REVOKE CERTIFICATES...

//Revoke the access token
client.revokeAccessToken();
```

Or you can try the authentication in constructor way:

```java
//Create an Authentication object with the user and password
final Authentication auth = Authentication.builder()
        .user("local:apiuser")
        .password("password")
        .build();

//Create a Config object setting the Authentication object
final Config config = Config.builder()
        .connectorType(ConnectorType.TPP_TOKEN)
        .baseUrl("https://tpp.venafi.example")
        .credentials(auth)
        .build();
        
//Create the client with the Config object. The client will be authenticated
//Internally the access token will be gotten and accessible 
//via the getTokenInfo() method.
final VCertTknClient client = new VCertTknClient(config);

///// REQUEST, RENEW, AND/OR REVOKE CERTIFICATES...

//Revoke the access token
client.revokeAccessToken();
```

:thumbsdown: To instantiate a client for Trust Protection Platform using deprecated username/password
authentication:

```java
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

## Prerequisites for using with Venafi as a Service

1. The Venafi as a Service REST API is accessible at [https://api.venafi.cloud](https://api.venafi.cloud/vaas) or [https://api.venafi.eu](https://api.venafi.eu/vaas) (if you have an EU account) from the system where VCert
will be executed.
2. You have successfully registered for a Venafi as a Service account, have been granted at least the
OutagePREDICT "Resource Owner" role, and know your API key.
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
4. An OutagePREDICT Application exists where you are among the owners, and you know the Application Name.
5. An Issuing Template is assigned to the Application, and you know its API Alias.

## Acceptance Tests

To run the acceptance tests the following environment variables must be set:

| NAME | NOTES |
|------|-------|
| TPPURL | Only for TPP connector tests (e.g. https://tpp.venafi.example/vedsdk) |
| TPP_TOKEN_URL | Only for TPP connector tests involving token auth (e.g. https://tpp.venafi.example) |
| TPPUSER | Only for TPP connector tests |
| TPPPASSWORD | Only for TPP connector tests |
| TPPZONE | Policy folder for TPP |
| CLOUDURL | Only for Venafi as a Service tests |
| APIKEY | Obtained by logging into Venafi as a Service after registering |
| CLOUDZONE | Zone ID or ProjectName\ZoneName for Venafi as a Service |
| CLOUDZONE2 | Zone ID or ProjectName\ZoneName for Venafi as a Service for testing empty OU, O, L, ST, and C |

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
