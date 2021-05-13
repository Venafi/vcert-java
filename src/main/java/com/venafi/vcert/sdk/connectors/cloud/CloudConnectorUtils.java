package com.venafi.vcert.sdk.connectors.cloud;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.connectors.cloud.domain.Application;
import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import com.venafi.vcert.sdk.connectors.cloud.domain.CloudZone;
import com.venafi.vcert.sdk.connectors.cloud.domain.UserDetails;
import com.venafi.vcert.sdk.connectors.cloud.endpoint.*;
import com.venafi.vcert.sdk.policy.api.domain.CloudPolicy;
import feign.FeignException;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.*;

public class CloudConnectorUtils {

    public static void setCit(String policyName, CertificateIssuingTemplate cit, CloudPolicy.CAInfo caInfo, String apiKey, Cloud cloud) throws VCertException {

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

        setCitToApp(policyName, cit, apiKey, cloud);
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

    public static void setCitToApp(String policyName, CertificateIssuingTemplate cit/*, CloudPolicy.CAInfo caInfo*/, String apiKey, Cloud cloud) throws VCertException {
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
            createAppForCit(cit, zone.appName(), apiKey, cloud);
        else //update the application with the relation to the cit if that is not existing
            addCitToApp(cit, application, apiKey, cloud);
    }

    private static void createAppForCit(CertificateIssuingTemplate cit, String appName, String apiKey, Cloud cloud) throws VCertException {
        UserDetails userDetails = cloud.authorize(apiKey);

        String userId = userDetails.user().id();

        Application application = new Application();

        Application.OwnerIdsAndType ownerIdsAndType = new Application.OwnerIdsAndType();
        ownerIdsAndType.ownerId(userId);
        ownerIdsAndType.ownerType("USER");
        List<Application.OwnerIdsAndType> ownerIdsAndTypes = new ArrayList<>();
        ownerIdsAndTypes.add(ownerIdsAndType);

        Map<String, String> citAliasIdMap = new HashMap<>();
        citAliasIdMap.put(cit.name(), cit.id());

        application.name(appName);
        application.ownerIdsAndTypes(ownerIdsAndTypes);
        application.certificateIssuingTemplateAliasIdMap(citAliasIdMap);

        cloud.createApplication(application, apiKey);
    }

    private static void addCitToApp(CertificateIssuingTemplate cit, Application application, String apiKey, Cloud cloud) throws VCertException {
        Map<String, String> citAliasIdMap = null;

        if ( application.certificateIssuingTemplateAliasIdMap() != null )
            citAliasIdMap = application.certificateIssuingTemplateAliasIdMap();
        else {
            citAliasIdMap = new HashMap<>();
            application.certificateIssuingTemplateAliasIdMap( citAliasIdMap );
        }

        //if the App doesn't contains the relation to the cit
        if ( !citAliasIdMap.containsKey(cit.name()) ) {
            //adding the reference to the cit
            citAliasIdMap.put(cit.name(), cit.id());

            //getting the appId because it will used to invoke the API to update the related Application
            String appId = application.id();

            //The id, companyId, fqDns and internalFqDns needs to be null in the request to update the Application
            // so therefore these attributes are set to null
            application.id(null);
            application.companyId(null);
            application.fqDns(null);
            application.internalFqDns(null);

            cloud.updateApplication(application, appId, apiKey);
        }
    }

    public static CloudPolicy getCloudPolicy( String policyName, String apiKey, Cloud cloud) throws VCertException{
        CloudPolicy cloudPolicy = new CloudPolicy();

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
                .get()
                .productName();
    }

    @Data
    @AllArgsConstructor
    //Class to hold required info which is extracted by the method getAccountInfo
    public static class CAAccountInfo {
        private String productId;
        private Integer organizationId;
    }
}
