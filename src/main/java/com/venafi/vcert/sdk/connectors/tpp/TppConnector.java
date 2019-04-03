package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.*;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.Is;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import java.security.KeyStore;
import java.time.OffsetDateTime;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class TppConnector implements Connector {

    private final Tpp tpp;
    @Getter
    private String apiKey;

    private static final Pattern policy = Pattern.compile("^\\\\VED\\\\Policy");
    private static final Pattern path = Pattern.compile("^\\\\");

    @VisibleForTesting
    OffsetDateTime bestBeforeEnd;

    @Getter
    private String zone;
    private static final String tppAttributeManagementType = "Management Type";
    private static final String tppAttributeManualCSR = "Manual Csr";

    TppConnector(Tpp tpp) {
        this.tpp = tpp;
    }

    @Override
    public ConnectorType getType() {
        return ConnectorType.TPP;
    }

    @Override
    public void setBaseUrl(String url) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public void setZone(String zone) {
        this.zone = zone;
    }

    @Override
    public void ping() throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    public void authenticate(Authentication auth) throws VCertException {
        VCertException.throwIfNull(auth, "failed to authenticate: missing credentials");
        AuthorizeResponse response = tpp.authorize(new AuthorizeRequest(auth.user(), auth.password()));
        apiKey = response.apiKey();
        bestBeforeEnd = response.validUntil();
    }

    @Override
    public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
        VCertException.throwIfNull(zone, "empty zone");
        ReadZoneConfigurationRequest request = new ReadZoneConfigurationRequest(getPolicyDN(zone));
        ReadZoneConfigurationResponse response = tpp.readZoneConfiguration(request, apiKey);
        ServerPolicy serverPolicy = response.policy();
        Policy policy = serverPolicy.toPolicy();
        ZoneConfiguration zoneConfig = serverPolicy.toZoneConfig();
        zoneConfig.policy(policy);
        return zoneConfig;
    }

    /** Register does nothing for TTP */
    @Override
    public void register(String eMail) throws VCertException {
    }

    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request) throws VCertException {
        if(config == null) {
            config = readZoneConfiguration(zone);
        }
        String tppMgmtType = config.customAttributeValues().get(tppAttributeManagementType);
        if("Monitoring".equals(tppMgmtType) || "Unassigned".equals(tppMgmtType)) {
            throw new VCertException("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed");
        }

        config.updateCertificateRequest(request);

        switch (request.csrOrigin()) {
            case LocalGeneratedCSR: {
                if ("0".equals(config.customAttributeValues().get(tppAttributeManualCSR))) {
                    throw new VCertException("Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0");
                }
                request.generatePrivateKey();
                request.generateCSR();
                break;
            }
            case UserProvidedCSR: {
                if("0".equals(config.customAttributeValues().get(tppAttributeManualCSR))) {
                    throw new VCertException("Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0");
                }
                request.generatePrivateKey();
                if(Is.blank(request.csr())) {
                    throw new VCertException("CSR was supposed to be provided by user, but it's empty");
                }
                break;
            }
            case ServiceGeneratedCSR: {
                request.csr(null);
                break;
            }
        }
        return request;
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public KeyStore retrieveCertificate(CertificateRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public String renewCertificate(RenewalRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public ImportResponse importCertificate(ImportRequest request) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    @Override
    public Policy readPolicyConfiguration(String zone) throws VCertException {
        throw new UnsupportedOperationException("Method not yet implemented");
    }

    private String getPolicyDN(final String zone) {
        String result = zone;
        Matcher candidate = policy.matcher(zone);
        if(!candidate.matches()) {
            if(!policy.matcher(zone).matches()) {
                result = "\\" + result;
            }
            result = "\\VED\\Policy" + result;
        }
        return result;
    }

    @Data
    @AllArgsConstructor
    static class AuthorizeRequest {
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class ReadZoneConfigurationRequest {
        String policyDN;
    }

    @Data
    @SuppressWarnings("WeakerAccess")
    public static class ReadZoneConfigurationResponse {
        Object error;
        ServerPolicy policy;
    }
}
