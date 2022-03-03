package com.venafi.vcert.sdk.connectors.tpp;

import static org.apache.commons.lang3.StringUtils.isBlank;

import java.util.Map;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.CharStreams;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.ImportRequest;
import com.venafi.vcert.sdk.certificate.ImportResponse;
import com.venafi.vcert.sdk.connectors.ConnectorException.FailedToRevokeTokenException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingAccessTokenException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingCredentialsException;
import com.venafi.vcert.sdk.connectors.ConnectorException.MissingRefreshTokenException;
import com.venafi.vcert.sdk.connectors.TokenConnector;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRenewalResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRequestResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRetrieveResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateRevokeResponse;
import com.venafi.vcert.sdk.connectors.tpp.Tpp.CertificateSearchResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCaTemplateRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCaTemplateResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequestResponse;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveResponse;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

import feign.FeignException;
import feign.FeignException.BadRequest;
import feign.FeignException.Unauthorized;
import feign.Response;
import lombok.Setter;

public class TppTokenConnector extends TppConnector implements TokenConnector {

    @Setter
    @VisibleForTesting
    private Authentication credentials;
    
    private TokenInfo tokenInfo;

    public TppTokenConnector(Tpp tpp){ super(tpp); }

    @Override
    public ConnectorType getType() {
        return ConnectorType.TPP_TOKEN;
    }
    
    private String getAuthHeaderValue() throws VCertException {
        if( isEmptyToken() )
        	throw new MissingAccessTokenException();

        return String.format(HEADER_VALUE_AUTHORIZATION, credentials.accessToken());
    }
    
	@Override
	public void authenticate(Authentication auth) throws VCertException {
		if(isEmptyCredentials(auth))
            throw new MissingCredentialsException();
		
        try {
            AuthorizeTokenRequest authRequest =
                new AuthorizeTokenRequest(auth.user(), auth.password(), auth.clientId(), auth.scope(), auth.state(),
                    auth.redirectUri());
            AuthorizeTokenResponse response = tpp.authorizeToken(authRequest);
            tokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(),
                response.tokenType(), response.scope(), response.identity(), response.refreshUntil(), true, null);

            this.credentials = auth;
            this.credentials.accessToken(tokenInfo.accessToken());
            this.credentials.refreshToken(tokenInfo.refreshToken());
        } catch(Unauthorized | BadRequest e){
            tokenInfo = new TokenInfo(null, null, -1, null, null,
                null, -1, false, e.getMessage() + " " + new String(e.content()) );
        }
	}
	
	@Override
	public TokenInfo getTokenInfo() throws VCertException {
		return tokenInfo;
	}

    @Override
    public TokenInfo getAccessToken(Authentication auth) throws VCertException {
        authenticate(auth);
        return getTokenInfo();
    }

    @Override
    public TokenInfo getAccessToken() throws VCertException {
        return getAccessToken(credentials);
    }

    @Override
    public TokenInfo refreshAccessToken(String clientId ) throws VCertException{
        if(isBlank(credentials.refreshToken()))
            throw new MissingRefreshTokenException();
        
        try {
            RefreshTokenRequest request = new RefreshTokenRequest(credentials.refreshToken(), clientId);
            RefreshTokenResponse response = tpp.refreshToken( request );

             tokenInfo = new TokenInfo(response.accessToken(), response.refreshToken(), response.expire(),
                    response.tokenType(), response.scope(), "", response.refreshUntil(), true, null);

            this.credentials.accessToken(tokenInfo.accessToken());
            this.credentials.refreshToken(tokenInfo.refreshToken());

            return tokenInfo;
        }catch (FeignException.BadRequest e){
            tokenInfo = new TokenInfo(null, null, -1, null, null,
                null, -1, false, e.getMessage() + " " + new String(e.content()));
        }
        return tokenInfo;
    }

    @Override
    public int revokeAccessToken() throws VCertException {
    	
        String requestHeader = getAuthHeaderValue();//"Bearer "+accessToken;

        Response response = tpp.revokeToken( requestHeader );
        if(response.status() == 200){
            return response.status();
        }else{
            throw new FailedToRevokeTokenException(response.reason());
        }
    }
  
    private boolean isEmptyCredentials(Authentication credentials){
        if(credentials == null){
            return true;
        }

        if(credentials.user() == null || credentials.user().isEmpty()){
            return true;
        }

        if(credentials.password() == null || credentials.password().isEmpty()){
            return true;
        }

        return false;
    }

    private boolean isEmptyToken(){
        if(credentials == null || isBlank(credentials.accessToken())){
            return true;
        }

        return false;
    }

    @Override
    protected TppAPI getTppAPI() {
        if(tppAPI == null){

            tppAPI = new TppAPI(tpp) {

            	@Override
                public String getAuthKey() throws VCertException {
                    return getAuthHeaderValue();
                }
            	
				@Override
				Response ping() throws VCertException {
					return tpp.pingToken(getAuthKey());
				}
            	
            	@Override
				ReadZoneConfigurationResponse readZoneConfiguration(ReadZoneConfigurationRequest request)
						throws VCertException {
					return tpp.readZoneConfigurationToken(request, getAuthKey());
				}

				@Override
				CertificateRequestResponse requestCertificate(CertificateRequestsPayload payload) throws VCertException {
					return tpp.requestCertificateToken(payload, getAuthKey());
				}

				@Override
				CertificateRetrieveResponse certificateRetrieve(CertificateRetrieveRequest request)
						throws VCertException {
					return tpp.certificateRetrieveToken(request, getAuthKey());
				}

				@Override
				CertificateSearchResponse searchCertificates(Map<String, String> searchRequest) throws VCertException {
					return tpp.searchCertificatesToken(searchRequest, getAuthKey());
				}

				@Override
				CertificateRevokeResponse revokeCertificate(CertificateRevokeRequest request) throws VCertException {
					return tpp.revokeCertificateToken(request, getAuthKey());
				}

				@Override
				CertificateRenewalResponse renewCertificate(CertificateRenewalRequest request) throws VCertException {
					return tpp.renewCertificateToken(request, getAuthKey());
				}

				@Override
				ImportResponse importCertificate(ImportRequest request) throws VCertException {
					return tpp.importCertificateToken(request, getAuthKey());
				}

                @Override
                public DNIsValidResponse dnIsValid(DNIsValidRequest request) throws VCertException {
                    return tpp.dnIsValidToken(request, getAuthKey());
                }

                @Override
                CreateDNResponse createDN(CreateDNRequest request) throws VCertException {
                    return tpp.createDNToken(request, getAuthKey());
                }

                @Override
                SetPolicyAttributeResponse setPolicyAttribute(SetPolicyAttributeRequest request) throws VCertException {
                    return tpp.setPolicyAttributeToken(request, getAuthKey());
                }

                @Override
                GetPolicyAttributeResponse getPolicyAttribute(GetPolicyAttributeRequest request) throws VCertException {
                    return tpp.getPolicyAttributeToken(request, getAuthKey());
                }

                @Override
                GetPolicyResponse getPolicy(GetPolicyRequest request) throws VCertException {
                    return tpp.getPolicyToken(request, getAuthKey());
                }

                @Override
                Response clearPolicyAttribute(ClearPolicyAttributeRequest request) throws VCertException {
                    return tpp.clearPolicyAttributeToken(request, getAuthKey());
                }

        		@Override
        		TppSshCertRequestResponse requestSshCertificate(TppSshCertRequest request) throws VCertException {
        			return tpp.requestSshCertificateToken(request, getAuthKey());
        		}

        		@Override
        		TppSshCertRetrieveResponse retrieveSshCertificate(TppSshCertRetrieveRequest request) throws VCertException {
        			return tpp.retrieveSshCertificateToken(request, getAuthKey());
        		}

				@Override
				String retrieveSshCAPublicKeyData(Map<String, String> params) throws VCertException {
					String publicKeyData = null;

					try {
						publicKeyData = CharStreams.toString(tpp.retrieveSshCAPublicKeyDataToken(params).body().asReader());
					} catch (Exception e) {
						throw new VCertException(e);
					}

					return publicKeyData;
				}

				@Override
				TppSshCaTemplateResponse retrieveSshCATemplate(TppSshCaTemplateRequest request) throws VCertException {
					return tpp.retrieveSshCATemplateToken(request, getAuthKey());
				}
            };
        }

        return tppAPI;
    }
}
