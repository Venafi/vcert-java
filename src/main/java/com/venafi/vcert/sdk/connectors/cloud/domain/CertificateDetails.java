package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.List;

import lombok.Data;

@Data
public class CertificateDetails {
	private String id;
	private String companyId;
	private String managedCertificateId;
	private String certificateRequestId;
	private String fingerprint;
	private List<String> issuerCertificateIds;
	private String certificateStatus;
	private String modificationDate;
	private String validityStart;
	private String validityEnd;
	private String selfSigned;
	private String signatureAlgorithm;
	private String signatureHashAlgorithm;
	private String encryptionType;
	private String keyStrength;
	private String subjectKeyIdentifierHash;
	private String authorityKeyIdentifierHash;
	private String serialNumber;
	private String subjectDN;
	private List<String> subjectCN;
	private List<String> subjectOU;
	private String subjectST;
	private String subjectL;
	private String subjectC;
	private String SubjectAlternativeNamesByType;
	private String issuerDN;
	private List<String> issuerCN;
	private List<String> issuerOU;
	private String issuerC;
	private List<String> keyUsage;
	private Boolean ocspNoCheck;
	private String versionType;
	private int totalInstanceCount;
	private int totalActiveInstanceCount;
	

	
	@Data
	public static class SubjectAlternativeNamesByType {
		private List<String> otherName;
		private List<String> rfc822Name;
		private List<String> dNSName;
		private List<String> x400Address;
		private List<String> directoryName;
		private List<String> ediPartyName;
		private List<String> uniformResourceIdentifier;
		private List<String> iPAddress;
		private List<String> registeredID;

	}

}
