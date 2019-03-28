package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.tpp.ZoneConfiguration;
import com.venafi.vcert.sdk.endpoint.Authentication;
import lombok.Getter;

import java.util.Arrays;
import java.util.Collection;


public class CloudConnector implements Connector {

    private Cloud cloud;

    @Getter
    private UserDetails user;
    private Authentication auth;

    CloudConnector(Cloud cloud) {
        this.cloud = cloud;
    }

    @Override
    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        this.auth = auth;
        this.user = cloud.authorize(auth.apiKey());
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String tag) throws VCertException {
        VCertException.throwIfNull(tag, "empty zone name");
        Zone zone = getZoneByTag(tag);
        CertificatePolicy policy = getPoliciesById(Arrays.asList(zone.defaultCertificateIdentityPolicy(), zone.defaultCertificateUsePolicy()));
        return zone.getZoneConfiguration(user, policy);
    }

    private CertificatePolicy getPoliciesById(Collection<String> ids) throws VCertException {
        CertificatePolicy policy = new CertificatePolicy();
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        for(String id : ids) {
            CertificatePolicy certificatePolicy = cloud.policyById(id, auth.apiKey());
            switch (certificatePolicy.certificatePolicyType()) {
                case "CERTIFICATE_IDENTITY": {
                    policy.subjectCNRegexes(certificatePolicy.subjectCNRegexes());
                    policy.subjectORegexes(certificatePolicy.subjectORegexes());
                    policy.subjectOURegexes(certificatePolicy.subjectOURegexes());
                    policy.subjectSTRegexes(certificatePolicy.subjectSTRegexes());
                    policy.subjectLRegexes(certificatePolicy.subjectLRegexes());
                    policy.subjectCRegexes(certificatePolicy.subjectCRegexes());
                    policy.sanRegexes(certificatePolicy.sanRegexes());
                    break;
                }
                case "CERTIFICATE_USE": {
                    policy.keyTypes(certificatePolicy.keyTypes());
                    policy.keyReuse(certificatePolicy.keyReuse());
                    break;
                }
                default: throw new IllegalArgumentException(String.format("unknown type %s", certificatePolicy.certificatePolicyType()));
            }
        }
        return policy;
    }

    private Zone getZoneByTag(String zone) throws VCertException {
        VCertException.throwIfNull(user, "must be authenticated to read the zone configuration");
        return cloud.zoneByTag(zone, auth.apiKey());
    }
}
