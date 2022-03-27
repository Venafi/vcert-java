package com.venafi.vcert.sdk;

import com.google.common.annotations.VisibleForTesting;

import feign.FeignException;

import com.venafi.vcert.sdk.connectors.Connector;
import com.venafi.vcert.sdk.connectors.TokenConnector;
import com.venafi.vcert.sdk.connectors.tpp.TokenInfo;
import com.venafi.vcert.sdk.connectors.tpp.Tpp;
import com.venafi.vcert.sdk.connectors.tpp.TppTokenConnector;
import com.venafi.vcert.sdk.endpoint.Authentication;

public class VCertTknClient extends VCertClient implements TokenConnector {

    public VCertTknClient(Config config) throws VCertException {
       super(config);
    }

    @Override
    protected Connector createConnector(Config config) throws VCertException {
    	Connector connector;
    	switch (config.connectorType()) {
    	case TPP_TOKEN:{
    		connector = new TppTokenConnector(Tpp.connect(config));
    		//((TppTokenConnector) connector).credentials(config.credentials());
    		break;
    	}
    	default:
    		throw new VCertException("ConnectorType is not defined");
    	}

    	return connector;
    }

	@VisibleForTesting
    VCertTknClient(TokenConnector connector) {
        super(connector);
    }

	@Override
	public TokenInfo getTokenInfo() throws VCertException {
		return ((TokenConnector)connector).getTokenInfo();
	}

    //=========================================================================================\\
    //=============================== VENAFI 20.2 OAUTH METHODS ===============================\\
    //=========================================================================================\\

    @Override
    public TokenInfo getAccessToken(Authentication auth) throws VCertException{
        try {
            return ((TokenConnector)connector).getAccessToken(auth);
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public TokenInfo getAccessToken() throws VCertException{
        try {
            return ((TokenConnector)connector).getAccessToken();
        } catch (FeignException e) {
            throw VCertException.fromFeignException(e);
        }
    }

    @Override
    public TokenInfo refreshAccessToken(String applicationId) throws VCertException {
        return  ((TokenConnector)connector).refreshAccessToken(applicationId);
    }

    @Override
    public int revokeAccessToken() throws VCertException {
        return ((TokenConnector)connector).revokeAccessToken();
    }
}
