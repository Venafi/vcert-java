package com.venafi.vcert.sdk.connectors.tpp;

import com.venafi.vcert.sdk.SignatureAlgorithm;
import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.certificate.EllipticCurve;
import com.venafi.vcert.sdk.certificate.KeyType;
import com.venafi.vcert.sdk.connectors.Policy;
import com.venafi.vcert.sdk.endpoint.AllowedKeyConfiguration;
import com.venafi.vcert.sdk.utils.Is;
import lombok.Data;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Data
// TODO move up one package
public class ZoneConfiguration {

    private String organization;
    private List<String> organizationalUnit;
    private String country;
    private String province;
    private String locality;
    private Policy policy = new Policy(); // Go merges the policy struct into the ZoneConfiguration one...
    private SignatureAlgorithm hashAlgorithm = SignatureAlgorithm.UnknownSignatureAlgorithm;

    private Map<String, String> customAttributeValues = new HashMap<>(); // Go SDK factory sets an empty map


    /**
     * UpdateCertificateRequest updates a certificate request based on the zone configurataion retrieved from the remote endpoint
     * @return
     */
    public void updateCertificateRequest(CertificateRequest request) {
        CertificateRequest.PKIXName subject = request.subject();
        subject.organization(Entity.of(subject.organization(), organization).resolve());
        if(Is.blank(subject.organizationalUnit()) && !Is.blank(organizationalUnit)) {
            subject.organizationalUnit(organizationalUnit);
        }
        subject.country(Entity.of(subject.country(), country).resolve());
        subject.province(Entity.of(subject.province(), province).resolve());
        subject.locality(Entity.of(subject.locality(), locality).resolve());
        if(hashAlgorithm != SignatureAlgorithm.UnknownSignatureAlgorithm) {
            request.signatureAlgorithm(hashAlgorithm);
        } else {
            request.signatureAlgorithm(SignatureAlgorithm.SHA256WithRSA);
        }

        if(!Is.blank(policy.allowedKeyConfigurations())) {
            boolean foundMatch = false;
            for(AllowedKeyConfiguration keyConf : policy.allowedKeyConfigurations()) {
                if(keyConf.keyType() == request.keyType()) {
                    foundMatch = true;
                    switch (request.keyType()) {
                        case ECDSA: {
                            if(!Is.blank(keyConf.keyCurves())) {
                                request.keyCurve(keyConf.keyCurves().get(0));
                            } else {
                                request.keyCurve(EllipticCurve.ellipticCurveDefault());
                            }
                            break;
                        }
                        case RSA: {
                            if(!Is.blank(keyConf.keySizes())) {
                                boolean sizeOK = false;
                                for(Integer size : keyConf.keySizes()) {
                                    if(size.equals(request.keyLength())) {
                                        sizeOK = true;
                                    }
                                }
                                if(!sizeOK) {
                                    List<Integer> reversedKeySizes = new ArrayList<>(keyConf.keySizes()); // not reversing the original
                                    reversedKeySizes.sort(Collections.reverseOrder());
                                    request.keyLength(reversedKeySizes.get(0));
                                }
                            } else {
                                request.keyLength(keyConf.keySizes().get(0));
                            }
                            break;
                        }
                    }
                }
            }
            if(!foundMatch) {
                AllowedKeyConfiguration configuration = policy.allowedKeyConfigurations().get(0);
                request.keyType(configuration.keyType());
                switch (request.keyType()) {
                    case ECDSA: {
                        if(!Is.blank(configuration.keyCurves())) {
                            request.keyCurve(configuration.keyCurves().get(0));
                        } else {
                            request.keyCurve(EllipticCurve.ellipticCurveDefault());
                        }
                        break;
                    }
                    case RSA: {
                        if(!Is.blank(configuration.keySizes())) {
                            List<Integer> reversedKeySizes = new ArrayList<>(configuration.keySizes());
                            reversedKeySizes.sort(Comparator.reverseOrder());
                            request.keyLength(reversedKeySizes.get(0));
                        } else {
                            request.keyLength(2048);
                        }
                        break;
                    }
                }
            }
        } else {
            // Zone config has no key length parameters, so we just pass user's -key-size or fall to default 2048
            if(KeyType.RSA.equals(request.keyType()) && request.keyLength() == 0) {
                request.keyLength(2048);
            }
        }
    }

    private static class Entity {
        private List<String> target;
        private String source;

        private Entity() {

        }
        static Entity of(List<String> target, String source) {
            Entity entity = new Entity();
            entity.target = target;
            entity.source = source;
            return entity;
        }
        List<String> resolve() {
            if(Is.blank(target) && !Is.blank(source)) {
                return Collections.singletonList(source);
            } else if(!Is.blank(target) && !Is.equalsFold(target.get(0), source)) {
                return Collections.singletonList(source);
            }
            return target;
        }
    }
    public boolean validateCertificateRequest(CertificateRequest request) throws VCertException {
        if(!isComponentValid(policy.subjectCNRegexes(), Collections.singletonList(request.subject().commonName()))) {
            throw new VCertException("The requested CN does not match any of the allowed CN regular expressions");
        }
        if(!isComponentValid(policy.subjectORegexes(), request.subject().organization())) {
            throw new VCertException("The requested Organization does not match any of the allowed Organization regular expressions");
        }
        if(!isComponentValid(policy.subjectOURegexes(), request.subject().organizationalUnit())) {
            throw new VCertException("The requested Organizational Unit does not match any of the allowed Organization Unit regular expressions");
        }
        if(!isComponentValid(policy.subjectSTRegexes(), request.subject().province())) {
            throw new VCertException("The requested State/Province does not match any of the allowed State/Province regular expressions");
        }
        if(!isComponentValid(policy.subjectLRegexes(), request.subject().locality())) {
            throw new VCertException("The requested Locality does not match any of the allowed Locality regular expressions");
        }
        if(!isComponentValid(policy.subjectCRegexes(), request.subject().country())) {
            throw new VCertException("The requested Country does not match any of the allowed Country regular expressions");
        }
        if(!isComponentValid(policy.dnsSanRegExs(), request.dnsNames())) {
            throw new VCertException("The requested Subject Alternative Name does not match any of the allowed Country regular expressions");
        }
        //todo (from Go SDK): add ip, email and over checking

        List<AllowedKeyConfiguration> allowedKeyConfigurations = policy.allowedKeyConfigurations();
        if(allowedKeyConfigurations != null && allowedKeyConfigurations.size() > 0) {
            boolean match = false;
            for(AllowedKeyConfiguration keyConfiguration : allowedKeyConfigurations) {
                if(keyConfiguration.keyType() == request.keyType()) {
                    if(request.keyLength() > 0) {
                        for(Integer size : keyConfiguration.keySizes()) {
                            if(size.equals(request.keyLength())) {
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
            throw new VCertException("The requested Key Type and Size do not match any of the allowed Key Types and Sizes");
        }

        return true;
    }

    private boolean isComponentValid(Collection<String> regexes, Collection<String> components) {
        if(regexes.size() == 0 || components.size() == 0) {
            return true;
        }

        for(String regex : regexes) {
            Pattern pattern;
            try {
                pattern = Pattern.compile(regex);
            } catch(PatternSyntaxException e) {
                // TODO log error
                return false;
            }
            for(String component : components) {
                Matcher m = pattern.matcher(component);
                if(m.matches()) {
                    return true; // todo: that seems wrong. Check if all policy rules need to be matched, or any one? (E.g.: Policy says location is [0]:Madrid,[1]:London -  does it need to match either or both?) Also, if we have locations 0:London, 1: Brussels, 2: Madrid, won't this pass? Should it?
                }
            }
        }
        return false;
    }
}


