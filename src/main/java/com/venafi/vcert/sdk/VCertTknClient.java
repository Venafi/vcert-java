package com.venafi.vcert.sdk;

import static org.apache.commons.lang3.StringUtils.isBlank;
import java.security.Security;
import com.google.common.annotations.VisibleForTesting;
import feign.FeignException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.certificate.RenewalRequest;
import com.venafi.vcert.sdk.certificate.RevocationRequest;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.connectors.TokenConnector;
import com.venafi.vcert.sdk.connectors.ZoneConfiguration;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.connectors.tpp.Tpp;
import com.venafi.vcert.sdk.connectors.tpp.TppTokenConnector;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;
import com.venafi.vcert.sdk.utils.VCertConstants;


public class VCertTknClient implements TokenConnector {

    private TokenConnector connector;

    public VCertTknClient(Config config) throws VCertException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        switch (config.connectorType()) {
            case TPP_TOKEN:
                connector = new TppTokenConnector(Tpp.connect(config));
                break;
            default:
                throw new VCertException("ConnectorType is not defined");
        }
        connector.setVendorAndProductName(isBlank(config.appInfo()) ? VCertConstants.DEFAULT_VENDOR_AND_PRODUCT_NAME :
            config.appInfo());
    }

    @VisibleForTesting
    VCertTknClient(TokenConnector connector) {
        this.connector = connector;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ConnectorType getType() {
        return connector.getType();
    }

    /**
     * Method not implemented yet.
     * Guaranteed to throw an exception.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void setBaseUrl(String url) throws VCertException {
        connector.setBaseUrl(url);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setZone(String zone) {
        connector.setZone(zone);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setVendorAndProductName(String vendorAndProductName) {
        connector.setVendorAndProductName(vendorAndProductName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getVendorAndProductName() {
        return connector.getVendorAndProductName();
    }

    //=========================================================================================\\
    //=============================== VENAFI 20.2 OAUTH METHODS ===============================\\
    //=========================================================================================\\

    @Override
    public TokenInfo getAccessToken(Authentication auth) throws VCertException{
        try {
            return connector.getAccessToken(auth);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    @Override
    public TokenInfo refreshAccessToken(String refreshToken, String applicationId) throws VCertException{
        return  connector.refreshAccessToken(refreshToken, applicationId);
    }

    @Override
    public int revokeAccessToken(String accessToken) throws VCertException {
        return connector.revokeAccessToken(accessToken);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void ping(String accessToken) throws VCertException {
        try {
            connector.ping(accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ZoneConfiguration readZoneConfiguration(String zone, String accessToken) throws VCertException {
        try {
            return connector.readZoneConfiguration(zone, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request, String accessToken)
            throws VCertException {
        try {
            return connector.generateRequest(config, request, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone, String accessToken) throws VCertException {
        try {
            return connector.requestCertificate(request, zone, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration, String accessToken)
            throws VCertException {
        try {
            return connector.requestCertificate(request, zoneConfiguration, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PEMCollection retrieveCertificate(CertificateRequest request, String accessToken) throws VCertException {
        try {
            return connector.retrieveCertificate(request, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void revokeCertificate(RevocationRequest request, String accessToken) throws VCertException {
        try {
            connector.revokeCertificate(request, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String renewCertificate(RenewalRequest request, String accessToken) throws VCertException {
        try {
            return connector.renewCertificate(request, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImportResponse importCertificate(ImportRequest request, String accessToken) throws VCertException {
        try {
            return connector.importCertificate(request, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Policy readPolicyConfiguration(String zone, String accessToken) throws VCertException {
        try {
            return connector.readPolicyConfiguration(zone, accessToken);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        } catch (Exception e) {
            throw new VCertException("Unexpected exception", e);
        }
    }
}
