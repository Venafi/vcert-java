# VCert-Java

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

VCert is a Java library, SDK, designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).



## Installation

The current version of this library can be install using

```
mvn install
```


## Usage

A basic example of createing a certificate using the VCert java implementation.

```
    final Config config = Config.builder()
            .connectorType(ConnectorType.CLOUD)
            .zone("Default")
            .build();

    final VCertClient client = new VCertClient(config);
    final ZoneConfiguration zoneConfiguration = client.readZoneConfiguration("Public");
    final Authentication auth = Authentication.builder()
            .apiKey("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            .build();

    CertificateRequest certificateRequest = new CertificateRequest().subject(
            new CertificateRequest.PKIXName()
                    .commonName("cert.example.com")
                    .organization(Collections.singletonList("Venafi, Inc."))
                    .organizationalUnit(Arrays.asList("Engineering"))
                    .country(Collections.singletonList("US"))
                    .locality(Collections.singletonList("SLC"))
                    .province(Collections.singletonList("Utah")))

            .keyType(KeyType.RSA);


    client.authenticate(auth);
    certificateRequest = client.generateRequest(zoneConfiguration, certificateRequest);
    String newCertId = client.requestCertificate(certificateRequest, "Public");
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

The requirement for the CA Template to be assigned by policy follows a long standing Venafi best practice which also met our design objective to keep the certificate request process simple for VCert users. If you require the abilty to specify the CA Template with the request you can use the TPP REST APIs but please be advised this goes against Venafi recommendations.

## Acceptance Tests

To run the acceptance tests the following environment variables must be set:

| NAME | NOTES |
|------|-------|
| VENAFI_USER | |
| VENAFI_PASSWORD | |
| VENAFI_TPP_URL | Only for TPP connector tests |
| VENAFI_API_KEY | Taken from account after logged in |
| VENAFI_CERT_COMMON_NAME | Used for cert creation, should match configured domains |
| VENAFI_CLOUD_URL | Only for cloud connector tests |
| VENAFI_ZONE | Only for cloud connector tests |

## Contributing to VCert

1. Fork it to your account (https://github.com/Venafi/vcert-java/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert-java.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert-java/pull/new/working-branch)


## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
