package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.ChainOption;
import com.venafi.vcert.sdk.certificate.DataFormat;
import com.venafi.vcert.sdk.certificate.PEMCollection;
import com.venafi.vcert.sdk.connectors.ConnectorException.KeyStoreUnzipedFilesBytesSizeExceeded;
import com.venafi.vcert.sdk.connectors.ConnectorException.KeyStoreZipCompressionRatioExceeded;
import com.venafi.vcert.sdk.connectors.ConnectorException.KeyStoreZipEntriesExceeded;
import com.venafi.vcert.sdk.connectors.ConnectorException.PolicyMatchException;
import com.venafi.vcert.sdk.connectors.cloud.CloudConnector.CsrAttributes;
import com.venafi.vcert.sdk.connectors.cloud.CloudConnector.SubjectAlternativeNamesByType;
import com.venafi.vcert.sdk.connectors.cloud.domain.*;
import com.venafi.vcert.sdk.connectors.cloud.endpoint.*;
import com.venafi.vcert.sdk.connectors.cloud.endpoint.CAAccount.ProductOption;
import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import com.venafi.vcert.sdk.policy.domain.PolicySpecification;

import feign.FeignException;
import lombok.AllArgsConstructor;
import lombok.Data;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.PrivateKey;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bouncycastle.openssl.PEMParser;

public class CloudConnectorUtils {

    public static void setCit(String policyName, CertificateIssuingTemplate cit, CloudPolicy.CAInfo caInfo,
							  String[] usersList, String apiKey, Cloud cloud) throws VCertException {

        CloudZone cloudZone = new CloudZone(policyName);
        cit.name(cloudZone.citAlias());

        //getting the CAProductOptionId
        CAAccountInfo caAccountInfo = CloudConnectorUtils.getCAAccountInfo(caInfo, apiKey, cloud);
        String caProductOptionId = caAccountInfo.productId;

        if (caProductOptionId == null )
            throw new VCertException("Specified CA doesn't exist");

        //Setting the CAProductOptionId to the parsed cit
        cit.certificateAuthorityProductOptionId( caProductOptionId );

        //setting the OrganizationId if the CA is DIGICERT
        if ( caInfo.caType().equals(CloudConstants.DIGICERT_TYPE) )
            if ( caAccountInfo.organizationId != null )
                cit.product().organizationId( caAccountInfo.organizationId );
            else
                throw new VCertException( "It was not possible to determine the Organization Id from the DIGICERT Product." );

        //Getting the cit from the server
        CertificateIssuingTemplate citFromServer = CloudConnectorUtils.getCIT(cit.name(), apiKey, cloud);

        //if cit already exists
        if ( citFromServer != null ) { //update it
            // the citId can't put directly in the cit because it is not part of the format of the body request that the endpoint is waiting
            cloud.updateCIT(cit, citFromServer.id(), apiKey);
            cit.id(citFromServer.id());
        } else { //create it
            //setting the citId resulting of the creation of the cit
            cit.id( createCIT(cit, apiKey, cloud));
        }

        setCitToApp(policyName, cit, usersList, apiKey, cloud);
    }

    public static CAAccountInfo getCAAccountInfo(CloudPolicy.CAInfo caInfo, String apiKey, Cloud cloud) throws VCertException {

        String caProductOptionId = null;
        Integer organizationId = null;

        CAAccountsList caAccountsList = cloud.getCAAccounts(caInfo.caType(), apiKey);

        for ( CAAccount caAccount : caAccountsList.accounts() ) {
            if ( caAccount.account().key().equals(caInfo.caAccountKey()) )
                for ( CAAccount.ProductOption productOption : caAccount.productOptions()) {
                    if(productOption.productName().equals(caInfo.vendorProductName())) {
                        caProductOptionId = productOption.id();

                        if( caInfo.caType().equals( CloudConstants.DIGICERT_TYPE ) ) {
                            if ( productOption.productDetails() != null && productOption.productDetails().productTemplate() != null )
                                organizationId = productOption.productDetails().productTemplate().organizationId();
                        }
                        break;
                    }
                }
        }

        return new CAAccountInfo(caProductOptionId, organizationId);
    }

    public static CertificateIssuingTemplate getCIT( String citName, String apiKey, Cloud cloud ) throws VCertException {
        CertificateIssuingTemplate cit = null;

        CITsList citsList = cloud.getCITs(apiKey);

        for (CertificateIssuingTemplate certificateIssuingTemplate : citsList.certificateIssuingTemplates()) {
            if(certificateIssuingTemplate.name.equals(citName)){
                cit = certificateIssuingTemplate;
                break;
            }
        }

        return cit;
    }

    public static String createCIT(CertificateIssuingTemplate cit, String apiKey, Cloud cloud ) throws VCertException {
        CITsList response = cloud.createCIT(cit, apiKey);

        //the response will contain the cit created and therefore we will return the related id
        return response.certificateIssuingTemplates().get(0).id();
    }

    public static void setCitToApp(String policyName, CertificateIssuingTemplate cit, String[] usersList, String apiKey,
								   Cloud cloud) throws VCertException {
        //getting the cloud zone
        CloudZone zone = new CloudZone(policyName);

        Application application = null;
        try {
            application = cloud.applicationByName(zone.appName(), apiKey);
        } catch (FeignException exception) {
            if (exception.status() != 404) {
                throw exception;
            }
        }

        //if the applications doesn't exist, the response will contains an error with code 20215,
        // then it will needed to create it
        if( application == null )
            //create the application and related it with the cit
            createAppForCit(cit, zone.appName(), usersList, apiKey, cloud);
        else //update the application with the relation to the cit if that is not existing
            addCitToApp(cit, application, usersList, apiKey, cloud);
    }

    private static void createAppForCit(CertificateIssuingTemplate cit, String appName, String[] usersList,
										String apiKey, Cloud cloud) throws VCertException {
        Application application = new Application();

		// Obtaining the owners from the user list
		List<Application.OwnerIdsAndType> ownersList = CloudConnectorUtils.resolveOwners(usersList, apiKey, cloud);

        Map<String, String> citAliasIdMap = new HashMap<>();
        citAliasIdMap.put(cit.name(), cit.id());

        application.name(appName);
        application.ownerIdsAndTypes(ownersList);
        application.certificateIssuingTemplateAliasIdMap(citAliasIdMap);

        cloud.createApplication(application, apiKey);
    }

    private static void addCitToApp(CertificateIssuingTemplate cit, Application application, String[] usersList,
									String apiKey, Cloud cloud) throws VCertException {
        Map<String, String> citAliasIdMap = null;

        if ( application.certificateIssuingTemplateAliasIdMap() != null )
            citAliasIdMap = application.certificateIssuingTemplateAliasIdMap();
        else {
            citAliasIdMap = new HashMap<>();
            application.certificateIssuingTemplateAliasIdMap( citAliasIdMap );
        }

        //if the App doesn't contain the relation to the cit
        if ( !citAliasIdMap.containsKey(cit.name()) ) {
            //adding the reference to the cit
            citAliasIdMap.put(cit.name(), cit.id());

            //getting the appId because it will be used to invoke the API to update the related Application
            String appId = application.id();

            //The id, companyId, fqDns and internalFqDns needs to be null in the request to update the Application,
            //therefore these attributes are set to null
            application.id(null);
            application.companyId(null);
            application.fqDns(null);
            application.internalFqDns(null);

			// Updating the owners list
			List<Application.OwnerIdsAndType> ownersList =  CloudConnectorUtils.resolveOwners(usersList, apiKey, cloud);
			application.ownerIdsAndTypes(ownersList);

            cloud.updateApplication(application, appId, apiKey);
        }
    }

	private static List<Application.OwnerIdsAndType> resolveOwners(String[] usersList, String apiKey, Cloud cloud) {
		List<Application.OwnerIdsAndType> ownersList = new ArrayList<>();

		if (usersList == null) {
			// When no user is provided on the list, adds the current one as owner
			UserDetails userDetails = cloud.authorize(apiKey);
			String userId = userDetails.user().id();
			Application.OwnerIdsAndType currentOwner = new Application.OwnerIdsAndType();
			currentOwner.ownerId(userId);
			currentOwner.ownerType(CloudConstants.OWNER_TYPE_USER);
			ownersList.add(currentOwner);
		}
		else {
			// Resolving the usernames list
			// Creating a higher level Teams object to cache the response.
			Teams tResponse = null;
			for (String username: usersList) {
				UserResponse response = cloud.retrieveUser(username, apiKey);
				// If the name matches a user, create the entry
				if (response != null) {
					Application.OwnerIdsAndType owner = new Application.OwnerIdsAndType();
					owner.ownerId(response.users().get(0).id());
					owner.ownerType(CloudConstants.OWNER_TYPE_USER);
					ownersList.add(owner);
				}else{
					if (tResponse == null) {
						tResponse = cloud.retrieveTeams(apiKey);
					}
					if (tResponse != null) {
						for (Team t : tResponse.teams()) {
							if (t.name().equals(username)) {
								Application.OwnerIdsAndType owner = new Application.OwnerIdsAndType();
								owner.ownerId(t.id());
								owner.ownerType(CloudConstants.OWNER_TYPE_TEAM);
								ownersList.add(owner);
								break;
							}
						}
					}

				}
			}
		}
		return ownersList;
	}

    public static CloudPolicy getCloudPolicy( String policyName, String apiKey, Cloud cloud) throws VCertException{
        CloudPolicy cloudPolicy = new CloudPolicy();
		CloudZone zone = new CloudZone(policyName);

		Application app = cloud.applicationByName(zone.appName(), apiKey);
		if (app == null){
			throw new VCertException("Application "+ zone.appName() + " could not be found");
		}
		List<String> usersList = new ArrayList<>();
		Teams tResponse = null;
		for (Application.OwnerIdsAndType owner: app.ownerIdsAndTypes()) {
			if (owner.ownerType().equals(CloudConstants.OWNER_TYPE_USER)) {
				User user = cloud.retrieveUserById(owner.ownerId(), apiKey);
				usersList.add(user.username());
			}else if (owner.ownerType().equals(CloudConstants.OWNER_TYPE_TEAM)) {
				if (tResponse == null){
					// This validation caches the teams list, so we don't have to call
					// the teams' endpoint multiple times when iterating owners of type TEAM
					tResponse = cloud.retrieveTeams(apiKey);
				}
				if (tResponse != null){
					for (Team t : tResponse.teams()) {
						if (t.id().equals(owner.ownerId())){
							usersList.add(t.name());
							break;
						}
					}
				}
			}
		}
		cloudPolicy.owners(usersList.toArray(new String[0]));

        CertificateIssuingTemplate cit = getPolicy(policyName, apiKey, cloud);
        cloudPolicy.certificateIssuingTemplate( cit );
        cloudPolicy.caInfo(getCAInfo( cit, apiKey, cloud ));

        return cloudPolicy;
    }

    private static CertificateIssuingTemplate getPolicy(String policyName, String apiKey, Cloud cloud) throws VCertException {

        CloudZone zone = new CloudZone(policyName);

        return cloud.certificateIssuingTemplateByAppNameAndCitAlias(zone.appName(), zone.citAlias(), apiKey);
    }

    private static CloudPolicy.CAInfo getCAInfo( CertificateIssuingTemplate cit, String apiKey, Cloud cloud ) throws VCertException {
        CAAccount caAccount = cloud.getCAAccount(cit.certificateAuthority, cit.certificateAuthorityAccountId(), apiKey);

        return new CloudPolicy.CAInfo(cit.certificateAuthority, caAccount.account().key(), getProductName(caAccount, cit));
    }

    private static String getProductName(CAAccount caAccount, CertificateIssuingTemplate cit) {
        return caAccount.productOptions().stream()
                .filter(p -> p.id().equals(cit.certificateAuthorityProductOptionId))
                .findFirst()
                .orElse(new ProductOption())
                .productName();
    }
    
    public static CsrAttributes buildCsrAttributes(CertificateRequest request, PolicySpecification policySpecification) throws VCertException {
  	  CsrAttributes csrAttributes = new CsrAttributes();

  	  //computing the commonName
  	  String reqCN = request.subject()!=null && isNotBlank(request.subject().commonName()) ? request.subject().commonName() : null;

  	  if( reqCN!=null ) {
  		  //validating that the request.subject.cn matches with the policy domains
  		  String[] policyDomains = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.domains()).orElse(null);

  		  if (policyDomains!=null && !matchRegexes(reqCN, policyDomains)) 
  			  throw new PolicyMatchException("CN", reqCN, "domains", policyDomains);

  		  csrAttributes.commonName(reqCN);
  	  }

  	  //computing the organization
  	  List<String> reqOrganizations = Optional.ofNullable(request).map(req -> req.subject()).map(s -> s.organization()).orElse(null);

  	  if( reqOrganizations!=null && reqOrganizations.size() > 0) {
  		  String[] reqOrgsArray = reqOrganizations.toArray(new String[0]);

  		  //validating that the req.subject.organization matches with the policy orgs
  		  String[] policyOrgs = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.subject()).map(s -> s.orgs()).orElse(null);

  		  if (policyOrgs!=null && !matchRegexes(reqOrgsArray, policyOrgs)) 
  			  throw new PolicyMatchException("organization", reqOrgsArray, "organization", policyOrgs);

  		  csrAttributes.organization(reqOrgsArray[0]);
  	  } else {
  		  String defaultOrg = Optional.ofNullable(policySpecification).map(ps -> ps.defaults()).map(d -> d.subject()).map(s -> s.org()).orElse(null);

  		  if(isNotBlank(defaultOrg))
  			  csrAttributes.organization(defaultOrg);
  	  }
  	  
  	  //computing the organizational Units
  	  List<String> reqOrgUnits = Optional.ofNullable(request).map(req -> req.subject()).map(s -> s.organizationalUnit()).orElse(null);

  	  if( reqOrgUnits!=null && reqOrgUnits.size() > 0) {
  		  String[] reqOrgUnitsArray = reqOrgUnits.toArray(new String[0]);

  		  //validating that the req.subject.organizationalUnit matches with the policy orgUnits
  		  String[] policyOrgUnits = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.subject()).map(s -> s.orgUnits()).orElse(null);

  		  if (policyOrgUnits!=null && !matchRegexes(reqOrgUnitsArray, policyOrgUnits)) 
  			  throw new PolicyMatchException("org unit", reqOrgUnitsArray, "org unit", policyOrgUnits);

  		  csrAttributes.organizationalUnits(reqOrgUnitsArray);
  	  } else {
  		  String[] defaultOrgUnits = Optional.ofNullable(policySpecification).map(ps -> ps.defaults()).map(d -> d.subject()).map(s -> s.orgUnits()).orElse(null);

  		  if(defaultOrgUnits!=null && defaultOrgUnits.length>0)
  			  csrAttributes.organizationalUnits(defaultOrgUnits);
  	  }
  	  
  	  //computing the localities
  	  List<String> reqLocalities = Optional.ofNullable(request).map(req -> req.subject()).map(s -> s.locality()).orElse(null);

  	  if( reqLocalities!=null && reqLocalities.size() > 0) {
  		  String[] reqLocalitiesArray = reqLocalities.toArray(new String[0]);

  		  //validating that the req.subject.locality matches with the policy localities
  		  String[] policyLocalities = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.subject()).map(s -> s.localities()).orElse(null);

  		  if (policyLocalities!=null && !matchRegexes(reqLocalitiesArray, policyLocalities)) 
  			  throw new PolicyMatchException("locality", reqLocalitiesArray, "localities", policyLocalities);

  		  csrAttributes.locality(reqLocalitiesArray[0]);
  	  } else {
  		  String defaultLocality = Optional.ofNullable(policySpecification).map(ps -> ps.defaults()).map(d -> d.subject()).map(s -> s.locality()).orElse(null);

  		  if(isNotBlank(defaultLocality))
  			  csrAttributes.locality(defaultLocality);
  	  }
  	  
  	  //computing the province
  	  List<String> reqProvince = Optional.ofNullable(request).map(req -> req.subject()).map(s -> s.province()).orElse(null);

  	  if( reqProvince!=null && reqProvince.size() > 0) {
  		  String[] reqProvinceArray = reqProvince.toArray(new String[0]);

  		  //validating that the req.subject.province matches with the policy states
  		  String[] policyStates = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.subject()).map(s -> s.states()).orElse(null);

  		  if (policyStates!=null && !matchRegexes(reqProvinceArray, policyStates)) 
  			  throw new PolicyMatchException("state", reqProvinceArray, "states", policyStates);

  		  csrAttributes.state(reqProvinceArray[0]);
  	  } else {
  		  String defaultState = Optional.ofNullable(policySpecification).map(ps -> ps.defaults()).map(d -> d.subject()).map(s -> s.state()).orElse(null);

  		  if(isNotBlank(defaultState))
  			  csrAttributes.state(defaultState);
  	  }
  	  
  	  //computing the country
  	  List<String> reqCountries = Optional.ofNullable(request).map(req -> req.subject()).map(s -> s.country()).orElse(null);

  	  if( reqCountries!=null && reqCountries.size() > 0) {
  		  String[] reqCountriesArray = reqCountries.toArray(new String[0]);

  		  //validating that the req.subject.country matches with the policy countries
  		  String[] policyCountries = Optional.ofNullable(policySpecification).map(ps -> ps.policy()).map(p -> p.subject()).map(s -> s.countries()).orElse(null);

  		  if (policyCountries!=null && !matchRegexes(reqCountriesArray, policyCountries)) 
  			  throw new PolicyMatchException("state", reqCountriesArray, "states", policyCountries);

  		  csrAttributes.country(reqCountriesArray[0]);
  	  } else {
  		  String defaultCountry = Optional.ofNullable(policySpecification).map(ps -> ps.defaults()).map(d -> d.subject()).map(s -> s.country()).orElse(null);

  		  if(isNotBlank(defaultCountry))
  			  csrAttributes.country(defaultCountry);
  	  }
  	  
  	  if(request.dnsNames()!=null && request.dnsNames().size()>0) {
  		  SubjectAlternativeNamesByType subjectAlternativeNamesByType = new SubjectAlternativeNamesByType().dnsNames(request.dnsNames().toArray(new String[0]));
  		  csrAttributes.subjectAlternativeNamesByType(subjectAlternativeNamesByType);
  	  }

  	  return csrAttributes;
    }
    
    public static boolean matchRegexes(String subject, String[] regexes) {
    	return matchRegexes(new String[] {subject}, regexes);
    }
    
    public static boolean matchRegexes(String[] subjects, String[] regexes) {
    	boolean allSubjectsMatched = true;
    	
    	List<Pattern> patterns = new ArrayList<Pattern>();
    	
    	for (String regex : regexes) {
			patterns.add(Pattern.compile(regex));
		}
    	
    	for (String subject : subjects) {
    		boolean subjectMatched = false;
			for (Pattern pattern : patterns) {
				if(pattern.matcher(subject).matches()) {
					subjectMatched = true;
					break;
				}	
			}
			
			if(!subjectMatched) {
				allSubjectsMatched = false;
				break;
			}
		}
    	
    	return allSubjectsMatched;
    }
    
    public static String getVaaSChainOption(ChainOption chainOption) {
    	switch (chainOption) {
    	case ChainOptionRootFirst:
    		return "ROOT_FIRST";
    	case ChainOptionRootLast:
    	case ChainOptionIgnore:
    	default:
    		return "EE_FIRST";
    	}
    }
    
    public static PEMCollection getPEMCollectionFromKeyStoreAsStream(InputStream keyStoreAsInputStream, String certId, ChainOption chainOption, String keyPassword, DataFormat dataFormat) throws VCertException {
    	String certificateAsPem = null;
    	
    	String pemFileSuffix = null;
    	if(chainOption == ChainOption.ChainOptionRootFirst)
    		pemFileSuffix = "_root-first.pem";
    	else
    		pemFileSuffix = "_root-last.pem";

    	PrivateKey privateKey = null;

    	try (ZipInputStream zis = new ZipInputStream(keyStoreAsInputStream)) {
    		//The next constants are in order to be on safe about of the zip bomb attacks
    		final int MAX_ENTRIES = 10;//The expected number of files in the zip returned by the call to 
    							//the API "POST /outagedetection/v1/certificates/{id}/keystore"
    		final int MAX_UNZIPED_FILES_SIZE = 1000000; //1 MB
        	
        	int entriesCount = 0;
        	int unzipedAcumulatedSize = 0;
        	
    		ZipEntry zipEntry;
    		while ((zipEntry = zis.getNextEntry())!= null) {
    			
    			entriesCount++;
    			
    			//ZIP Bomb Attack validation
    			//If the number of entries is major that the expected max number of entries 
    			if(entriesCount > MAX_ENTRIES)
    				throw new KeyStoreZipEntriesExceeded(certId, MAX_ENTRIES);
    			
    			String zipEntryContent = readZipEntry(zipEntry, zis, certId);
    			
    			String fileName = zipEntry.getName();
    			if(fileName.endsWith(".key")) {
    				//Getting the PrivateKey in PKCS8 and decrypting it
    				PEMParser pemParser = new PEMParser(new StringReader(zipEntryContent));
    				privateKey = PEMCollection.decryptPKCS8PrivateKey(pemParser, keyPassword);
    			} else {
    				if(fileName.endsWith(pemFileSuffix)) {
    					certificateAsPem = zipEntryContent;
    				}
    			}
    			
    			unzipedAcumulatedSize += zipEntryContent.getBytes().length;
    			
    			//ZIP Bomb Attack validation
    			//If the sum of the number of bytes of the unzipped files is major that the expected 
    			//maximum number of bytes.
    			if (unzipedAcumulatedSize > MAX_UNZIPED_FILES_SIZE)
    				throw new KeyStoreUnzipedFilesBytesSizeExceeded(certId, MAX_UNZIPED_FILES_SIZE);
    		}
    	} catch (Exception e) {
    		throw new VCertException(e);
    	}

    	return PEMCollection.fromStringPEMCollection(
    			certificateAsPem, 
    			chainOption, 
    			privateKey,
    			keyPassword,
    			dataFormat);
    }
    
    private static String readZipEntry(ZipEntry zipEntry, ZipInputStream zis, String certId) throws VCertException, IOException {
    	
    	long totalSizeEntry = 0;

    	final int MAX_RATIO = 3;//It's expected that the compression ratio should't be more than 3

    	StringBuilder s = new StringBuilder();
    	byte[] buffer = new byte[1024];
    	int nBytes = 0;
    	while ((nBytes = zis.read(buffer, 0, 1024)) >= 0) {
    		s.append(new String(buffer, 0, nBytes));
    		
    		//ZIP Bomb Attack validation
    		//If the compression ratio of the current unzipped file is major that the expected 
    		// max ratio
    		totalSizeEntry += nBytes;
    		long compressionRatio = totalSizeEntry / zipEntry.getCompressedSize();
    		if(compressionRatio > MAX_RATIO) {
    			// ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
    			throw new KeyStoreZipCompressionRatioExceeded(certId, zipEntry.getName(), MAX_RATIO);
    		}
    	}

		return s.toString();
    }

    @Data
    @AllArgsConstructor
    //Class to hold required info which is extracted by the method getAccountInfo
    public static class CAAccountInfo {
        private String productId;
        private Integer organizationId;
    }
}
