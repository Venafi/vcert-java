package com.venafi.vcert.sdk.connectors.tpp;

import com.google.common.annotations.VisibleForTesting;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.ServerPolicy;
import com.venafi.vcert.sdk.endpoint.Authentication;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

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

    TppConnector(Tpp tpp) {
        this.tpp = tpp;
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
