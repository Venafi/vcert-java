package com.venafi.vcert.sdk.connectors.tpp;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.connectors.ConnectorException;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.*;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveRequest;
import com.venafi.vcert.sdk.connectors.tpp.endpoint.ssh.TppSshCertRetrieveResponse;
import com.venafi.vcert.sdk.policy.api.domain.TPPPolicy;
import com.venafi.vcert.sdk.policy.converter.tpp.AltName;
import feign.Response;

import java.util.ArrayList;
import java.util.List;



public class TppConnectorUtils {

	protected static final String SSH_CA_ROOT_PATH = "\\VED\\Certificate Authority\\SSH\\Templates";

	public static boolean dnExist(String dn, TppAPI tppAPI) throws VCertException {
		try {
			DNIsValidResponse dnIsValidResponse = tppAPI.dnIsValid(new DNIsValidRequest(dn));

			if(dnIsValidResponse.result() == 1 && dnIsValidResponse.objectDN().dn()!=null)
				return true;
			else
				if( dnIsValidResponse.error() != null && dnIsValidResponse.result() == 400)
					return false;
				else
					throw new VCertException(dnIsValidResponse.error());
		} catch (Exception e) {
			throw new VCertException(e);
		}
	}

	public static void createPolicy(String dn, TppAPI tppAPI) throws VCertException {
		try {
			CreateDNResponse createDNResponse = tppAPI.createDN(new CreateDNRequest(dn));

			if( createDNResponse.error() != null)
				throw new VCertException(createDNResponse.error());
		} catch (Exception e) {
			throw new VCertException(e);
		}
	}

	public static void resetAttributes(String policyName, TppAPI tppAPI) throws VCertException {
		//reset Contact
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_CONTACT, tppAPI);

		//reset Approver
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_APPROVER, tppAPI);

		//reset Domain Suffix Whitelist
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_DOMAIN_SUFFIX_WHITELIST, tppAPI);

		//reset Prohibit Wildcard
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_PROHIBIT_WILDCARD, tppAPI);

		//reset Certificate Authority
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_CERTIFICATE_AUTHORITY, tppAPI);

		//reset Management Type
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_MANAGEMENT_TYPE, tppAPI);

		//reset Organization attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_ORGANIZATION, tppAPI);

		//reset Organizational Unit attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_ORGANIZATIONAL_UNIT, tppAPI);

		//reset City attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_CITY, tppAPI);

		//reset State attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_STATE, tppAPI);

		//reset Country attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_COUNTRY, tppAPI);

		//reset Key Algorithm attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_KEY_ALGORITHM, tppAPI);

		//reset Key Bit Strength
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_KEY_BIT_STRENGTH, tppAPI);

		//reset Elliptic Curve attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_ELLIPTIC_CURVE, tppAPI);

		//reset Manual Csr attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_MANUAL_CSR, tppAPI);

		//reset prohibited SAN Types attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_PROHIBITED_SAN_TYPES, tppAPI);

		//reset Private Key Reuse" & "Want Renewal
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_ALLOW_PRIVATE_KEY_REUSE, tppAPI);

		//reset Want Renewal attribute
		clearPolicyAttribute(policyName, TppPolicyConstants.TPP_WANT_RENEWAL, tppAPI);
	}

	public static void setPolicyAttributes(TPPPolicy tppPolicy, TppAPI tppAPI) throws VCertException {
		//create Contact
		if (tppPolicy.contact() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CONTACT, tppPolicy.contact(), true, tppAPI);

		//create Approver
		if (tppPolicy.approver() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_APPROVER, tppPolicy.approver(), true, tppAPI);

		//create Domain Suffix Whitelist
		if (tppPolicy.domainSuffixWhiteList() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_DOMAIN_SUFFIX_WHITELIST, tppPolicy.domainSuffixWhiteList(), true, tppAPI);

		//create Prohibit Wildcard
		if (tppPolicy.prohibitWildcard() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_PROHIBIT_WILDCARD, new Integer[]{tppPolicy.prohibitWildcard()}, false, tppAPI);

		//create Certificate Authority
		if (tppPolicy.certificateAuthority() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CERTIFICATE_AUTHORITY, new String[]{tppPolicy.certificateAuthority()}, false, tppAPI);

		//create Management Type
		if (tppPolicy.managementType() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_MANAGEMENT_TYPE, tppPolicy.managementType().values(), tppPolicy.managementType().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_MANAGEMENT_TYPE, tppAPI);

		//create Organization attribute
		if (tppPolicy.organization() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATION, tppPolicy.organization().values(), tppPolicy.organization().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATION, tppAPI);

		//create Organizational Unit attribute
		if (tppPolicy.organizationalUnit() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATIONAL_UNIT, tppPolicy.organizationalUnit().values(), tppPolicy.organizationalUnit().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ORGANIZATIONAL_UNIT, tppAPI);

		//create City attribute
		if (tppPolicy.city() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CITY, tppPolicy.city().values(), tppPolicy.city().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_CITY, tppAPI);

		//create State attribute
		if (tppPolicy.state() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_STATE, tppPolicy.state().values(), tppPolicy.state().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_STATE, tppAPI);

		//create Country attribute
		if (tppPolicy.country() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_COUNTRY, tppPolicy.country().values(), tppPolicy.country().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_COUNTRY, tppAPI);

		//create Key Algorithm attribute
		if (tppPolicy.keyAlgorithm() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_ALGORITHM, tppPolicy.keyAlgorithm().values(), tppPolicy.keyAlgorithm().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_ALGORITHM, tppAPI);

		//create Key Bit Strength
		if (tppPolicy.keyBitStrength() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_BIT_STRENGTH, tppPolicy.keyBitStrength().values(), tppPolicy.keyBitStrength().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_KEY_BIT_STRENGTH, tppAPI);

		//create Elliptic Curve attribute
		if (tppPolicy.ellipticCurve() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ELLIPTIC_CURVE, tppPolicy.ellipticCurve().values(), tppPolicy.ellipticCurve().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ELLIPTIC_CURVE, tppAPI);

		//create Manual Csr attribute
		if (tppPolicy.manualCsr() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_MANUAL_CSR, tppPolicy.manualCsr().values(), tppPolicy.manualCsr().lock(), tppAPI);
		else
			clearPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_MANUAL_CSR, tppAPI);

		//create prohibited SAN Types attribute
		if (tppPolicy.prohibitedSANTypes() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_PROHIBITED_SAN_TYPES, tppPolicy.prohibitedSANTypes(), false, tppAPI);

		//Allow Private Key Reuse" & "Want Renewal
		if (tppPolicy.allowPrivateKeyReuse() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_ALLOW_PRIVATE_KEY_REUSE, tppPolicy.allowPrivateKeyReuse().values(), tppPolicy.allowPrivateKeyReuse().lock(), tppAPI);

		//create Want Renewal attribute
		if (tppPolicy.wantRenewal() != null)
			setPolicyAttribute(tppPolicy.policyName(), TppPolicyConstants.TPP_WANT_RENEWAL, tppPolicy.wantRenewal().values(), tppPolicy.wantRenewal().lock(), tppAPI);
	}

	public static void setPolicyAttribute(String dn, String attributeName, Object[] values, boolean locked, TppAPI tppAPI) throws VCertException {
		try {
			SetPolicyAttributeResponse setPolicyAttributeResponse = tppAPI.setPolicyAttribute(new SetPolicyAttributeRequest(dn, attributeName, values, locked));

			if(setPolicyAttributeResponse.result() != 1)
				throw new VCertException(setPolicyAttributeResponse.error());
		} catch (Exception e) {
			throw new VCertException(e);
		}
	}

	public static void clearPolicyAttribute(String dn, String attributeName, TppAPI tppAPI) throws VCertException {
		try {
			Response clearPolicyAttributeResponse = tppAPI.clearPolicyAttribute(new ClearPolicyAttributeRequest(dn, attributeName));

			if(clearPolicyAttributeResponse.status() != 200)
				throw new VCertException("It was no possible to reset the attribute "+attributeName);
		} catch (Exception e) {
			throw new VCertException(e);
		}
	}

	public static TPPPolicy populatePolicy(TPPPolicy tppPolicy, TppAPI tppAPI) throws VCertException {
		GetPolicyResponse getPolicyResponse;
		try {
			getPolicyResponse = tppAPI.getPolicy(new GetPolicyRequest(tppPolicy.policyName()));
		} catch (Exception e) {
			throw new VCertException(e);
		}

		if(getPolicyResponse != null && getPolicyResponse.error() != null)
			throw new VCertException(getPolicyResponse.error());

		PolicyResponse policyResponse = getPolicyResponse.policy();

		if ( policyResponse != null ){
			//Domain suffix white list
			tppPolicy.domainSuffixWhiteList( policyResponse.whitelistedDomains() );

			//Prohibited wildcard
			tppPolicy.prohibitWildcard( policyResponse.wildcardsAllowed() ? 0 : 1);

			//Certificate authority
			tppPolicy.certificateAuthority( policyResponse.certificateAuthority() != null ? policyResponse.certificateAuthority().value() : null);

			//management type
			if( policyResponse.managementType() != null)
				tppPolicy.managementType( policyResponse.managementType().value(), policyResponse.managementType().locked() );

			//Subject
			SubjectResponse subjectResponse = policyResponse.subject();

			if( subjectResponse != null ) {
				//Organization
				if ( subjectResponse.organization() != null )
					tppPolicy.organization( subjectResponse.organization().value(), subjectResponse.organization().locked());

				//Org Unit
				if ( subjectResponse.organizationalUnit() != null )
					tppPolicy.organizationalUnit( subjectResponse.organizationalUnit().values(), subjectResponse.organizationalUnit().locked() );

				//City
				if ( subjectResponse.city() != null )
					tppPolicy.city( subjectResponse.city().value(), subjectResponse.city().locked() );

				//State
				if ( subjectResponse.state() != null )
					tppPolicy.state( subjectResponse.state().value(), subjectResponse.state().locked() );

				//country
				if ( subjectResponse.country() != null )
					tppPolicy.country( subjectResponse.country().value(), subjectResponse.country().locked()  );
			}

			//KeyPair
			KeyPairResponse keyPairResponse = policyResponse.keyPair();

			if ( keyPairResponse != null ) {
				//KeyAlgorithm
				if( keyPairResponse.keyAlgorithm() != null )
					tppPolicy.keyAlgorithm( keyPairResponse.keyAlgorithm().value(), keyPairResponse.keyAlgorithm().locked());

				//Key Bit Strength
				if( keyPairResponse.keySize() != null )
					tppPolicy.keyBitStrength( keyPairResponse.keySize().value().toString(), keyPairResponse.keySize().locked() );


				//Elliptic Curve
				if( keyPairResponse.ellipticCurve() != null )
					tppPolicy.ellipticCurve( keyPairResponse.ellipticCurve().value(), keyPairResponse.ellipticCurve().locked() );
			}

			//Manual Csr
			if( policyResponse.csrGeneration() != null)
				if( policyResponse.csrGeneration().value().equals("ServiceGenerated") )
					tppPolicy.manualCsr("0", policyResponse.csrGeneration().locked());
				else
					if( policyResponse.csrGeneration().value().equals("UserProvided") )
						tppPolicy.manualCsr("1", policyResponse.csrGeneration().locked());

			//AllowPrivate Key Reuse
			tppPolicy.allowPrivateKeyReuse( policyResponse.privateKeyReuseAllowed() ? "1" : "0", true );

			//TppWantRenewal
			tppPolicy.wantRenewal( policyResponse.privateKeyReuseAllowed() ? "1" : "0", true );

			//Prohibited SAN Types
			setProhibitedSANTypes(tppPolicy, policyResponse);

			// Resolve contact names
			String[] usernames = TppConnectorUtils.retrieveUsernamesFromTPPContacts(tppPolicy.policyName(), tppAPI);
			tppPolicy.contact(usernames);
		}

		return tppPolicy;
	}

	private static String[] retrieveUsernamesFromTPPContacts(String policyName, TppAPI tppAPI) throws VCertException{
		GetPolicyAttributeResponse contactResponse;
		List<String> usersList = new ArrayList<>();

		try{
			contactResponse = tppAPI.getPolicyAttribute(new GetPolicyAttributeRequest(policyName,
					TppPolicyConstants.TPP_CONTACT));
		} catch (Exception e) {
			throw new VCertException(e);
		}
		if (contactResponse != null && contactResponse.error() != null){
			throw new ConnectorException.TppContactException(policyName, contactResponse.error());
		}
		if (contactResponse.values() != null) {
			Object[] contacts = contactResponse.values();
			for (Object prefixedUniversal : contacts) {
				try{
					ValidateIdentityResponse response = tppAPI.validateIdentity(
							new ValidateIdentityRequest(
									new IdentityInformation((String)prefixedUniversal)
							)
					);
					String username = response.id().name();
					usersList.add(username);
				} catch (Exception e) {
					throw new VCertException(e);
				}
			}
		}

		return usersList.toArray(new String[0]);
	}

	public static void setProhibitedSANTypes( TPPPolicy tppPolicy, PolicyResponse policyResponse ) {

		List<String> prohibitedSANTypes = new ArrayList<>();

		if ( policyResponse.subjAltNameDnsAllowed() )
			prohibitedSANTypes.add(AltName.DNS.value);

		if ( policyResponse.subjAltNameIpAllowed() )
			prohibitedSANTypes.add(AltName.IP.value);

		if ( policyResponse.subjAltNameEmailAllowed() )
			prohibitedSANTypes.add(AltName.EMAIL.value);

		if ( policyResponse.subjAltNameUriAllowed() )
			prohibitedSANTypes.add(AltName.URI.value);

		if ( policyResponse.subjAltNameUpnAllowed() )
			prohibitedSANTypes.add(AltName.UPN.value);

		if( prohibitedSANTypes.size()>0 )
			tppPolicy.prohibitedSANTypes(prohibitedSANTypes.toArray(new String[0]));
	}

	public static TppSshCertRequest convertToTppSshCertReq(SshCertificateRequest sshCertificateRequest) throws VCertException {
		TppSshCertRequest tppSshCertRequest = new TppSshCertRequest();

		tppSshCertRequest.cadn( isNotBlank(sshCertificateRequest.template()) ? getSshCADN(sshCertificateRequest.template()): null );
		tppSshCertRequest.policyDN( isNotBlank(sshCertificateRequest.policyDN()) ? sshCertificateRequest.policyDN() : null );
		tppSshCertRequest.objectName( isNotBlank(sshCertificateRequest.objectName()) ? sshCertificateRequest.objectName() : null );
		tppSshCertRequest.destinationAddresses( sshCertificateRequest.destinationAddresses() != null && sshCertificateRequest.destinationAddresses().length > 0 ? sshCertificateRequest.destinationAddresses() : null );
		tppSshCertRequest.keyId( isNotBlank(sshCertificateRequest.keyId()) ? sshCertificateRequest.keyId() : null );
		tppSshCertRequest.principals( sshCertificateRequest.principals() != null && sshCertificateRequest.principals().length > 0 ? sshCertificateRequest.principals() : null );
		tppSshCertRequest.validityPeriod( isNotBlank(sshCertificateRequest.validityPeriod()) ? sshCertificateRequest.validityPeriod() : null );
		tppSshCertRequest.publicKeyData( isNotBlank(sshCertificateRequest.publicKeyData()) ? sshCertificateRequest.publicKeyData() : null );
		tppSshCertRequest.extensions( sshCertificateRequest.extensions() != null && !sshCertificateRequest.extensions().isEmpty() ? sshCertificateRequest.extensions() : null );
		tppSshCertRequest.forceCommand( isNotBlank(sshCertificateRequest.forceCommand()) ? sshCertificateRequest.forceCommand() : null );
		tppSshCertRequest.sourceAddresses( sshCertificateRequest.sourceAddresses() != null && sshCertificateRequest.sourceAddresses().length > 0  ? sshCertificateRequest.sourceAddresses() : null );

		return tppSshCertRequest;
	}

	public static TppSshCertRetrieveRequest convertToTppSshCertRetReq(SshCertificateRequest sshCertificateRequest) throws VCertException {
		TppSshCertRetrieveRequest tppSshCertRetrieveRequest = new TppSshCertRetrieveRequest();

		tppSshCertRetrieveRequest.dn( isNotBlank(sshCertificateRequest.pickupID()) ? sshCertificateRequest.pickupID() : null );
		tppSshCertRetrieveRequest.guid( isNotBlank(sshCertificateRequest.guid()) ? sshCertificateRequest.guid() : null );
		tppSshCertRetrieveRequest.privateKeyPassphrase( isNotBlank(sshCertificateRequest.privateKeyPassphrase()) ? sshCertificateRequest.privateKeyPassphrase() : null );

		return tppSshCertRetrieveRequest;
	}

	public static SshCertRetrieveDetails convertToSshCertRetrieveDetails(TppSshCertRetrieveResponse tppSshCertRetrieveResponse) throws VCertException {
		SshCertRetrieveDetails sshCertRetrieveDetails = new SshCertRetrieveDetails();

		sshCertRetrieveDetails.certificateDetails( tppSshCertRetrieveResponse.certificateDetails() );
		sshCertRetrieveDetails.privateKeyData( tppSshCertRetrieveResponse.privateKeyData() );
		sshCertRetrieveDetails.publicKeyData( tppSshCertRetrieveResponse.publicKeyData() );
		sshCertRetrieveDetails.certificateData( tppSshCertRetrieveResponse.certificateData() );
		sshCertRetrieveDetails.guid( tppSshCertRetrieveResponse.guid() );
		sshCertRetrieveDetails.dn( tppSshCertRetrieveResponse.dn() );
		sshCertRetrieveDetails.caGuid( tppSshCertRetrieveResponse.caGuid() );
		sshCertRetrieveDetails.cadn( tppSshCertRetrieveResponse.cadn() );

		return sshCertRetrieveDetails;
	}

	public static String getSshCADN(final String cadn) {
		String result = cadn;

		result = result.startsWith("\\") ? result : "\\"+result;//Ensuring that the path to the CA DN starts with a "\"
		result = result.startsWith(SSH_CA_ROOT_PATH) ? result : SSH_CA_ROOT_PATH+result; //Ensuring that the CA DN starts with "\VED\Certificate Authority\SSH\Templates"

		return result;
	}

}
