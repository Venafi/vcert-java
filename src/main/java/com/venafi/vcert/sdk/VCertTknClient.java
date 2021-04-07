package com.venafi.vcert.sdk;

import static org.apache.commons.lang3.StringUtils.isBlank;

import java.io.File;
import java.nio.file.Path;
import java.security.Security;

import com.google.common.annotations.VisibleForTesting;

import com.venafi.vcert.sdk.policyspecification.domain.PolicySpecification;
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
            case TPP_TOKEN:{
                connector = new TppTokenConnector(Tpp.connect(config));
                ((TppTokenConnector) connector).credentials(config.credentials());
                break;
            }
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
        }
    }

    @Override
    public TokenInfo getAccessToken() throws VCertException{
        try {
            return connector.getAccessToken();
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public TokenInfo refreshAccessToken(String applicationId) throws VCertException {
        return  connector.refreshAccessToken(applicationId);
    }

    @Override
    public int revokeAccessToken() throws VCertException {
        return connector.revokeAccessToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void ping() throws VCertException {
        try {
            connector.ping();
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ZoneConfiguration readZoneConfiguration(String zone) throws VCertException {
        try {
            return connector.readZoneConfiguration(zone);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CertificateRequest generateRequest(ZoneConfiguration config, CertificateRequest request)
            throws VCertException {
        try {
            return connector.generateRequest(config, request);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public String requestCertificate(CertificateRequest request, String zone) throws VCertException {
        try {
            return connector.requestCertificate(request, zone);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String requestCertificate(CertificateRequest request, ZoneConfiguration zoneConfiguration)
            throws VCertException {
        try {
            return connector.requestCertificate(request, zoneConfiguration);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PEMCollection retrieveCertificate(CertificateRequest request) throws VCertException {
        try {
            return connector.retrieveCertificate(request);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void revokeCertificate(RevocationRequest request) throws VCertException {
        try {
            connector.revokeCertificate(request);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String renewCertificate(RenewalRequest request) throws VCertException {
        try {
            return connector.renewCertificate(request);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ImportResponse importCertificate(ImportRequest request) throws VCertException {
        try {
            return connector.importCertificate(request);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Policy readPolicyConfiguration(String zone) throws VCertException {
        try {
            return connector.readPolicyConfiguration(zone);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public void setPolicy(String policyName, Path filePath) throws VCertException {
        try {
            connector.setPolicy(policyName, filePath);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public void setPolicy(String policyName, String policySpecificationContent) throws VCertException {
        try {
            connector.setPolicy(policyName, policySpecificationContent);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public void setPolicy(String policyName, PolicySpecification policySpecification) throws VCertException {
        try {
            connector.setPolicy(policyName, policySpecification);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    //public File getPolicySpecificationFile(String policyName) throws VCertException {
    public File getPolicySpecificationFile(String policyName, Path filePath) throws VCertException {
        try {
            return connector.getPolicySpecificationFile(policyName, filePath);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public String getPolicySpecificationString(String policyName) throws VCertException {
        try {
            return connector.getPolicySpecificationString(policyName);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public PolicySpecification getPolicySpecification(String policyName) throws VCertException {
        try {
            return connector.getPolicySpecification(policyName);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }
}
