package com.venafi.vcert.sdk.certificate;

import java.util.Map;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

/**
 * The details of the requested certificate.
 * @author Marcos E. Albornoz Abud
 *
 */
@Data
public class SshCertificateDetails {
	
	/**
	 * The type of the key. E.g., ecdsa-sha2-nistp256-cert-v01@openssh.com
	 */
	@SerializedName("KeyType")
	private String keyType;
	/**
	 * Whether the issued certificate is for client or host authentication.
	 */
	@SerializedName("CertificateType")
	private String certificateType;
	/**
	 * Base-64 encoded SHA256 hash of the public key. Padding characters from end are trimmed.
	 */
	@SerializedName("PublicKeyFingerprintSHA256")
	private String publicKeyFingerprintSHA256;
	/**
	 * Base-64 encoded SHA256 hash of the issued certificate. Padding characters from end are trimmed.
	 */
	@SerializedName("CertificateFingerprintSHA256")
	private String certificateFingerprintSHA256;
	/**
	 * Base-64 encoded SHA256 hash of the public key of the CA used for signing the requested certificate. 
	 * Padding characters from end are trimmed.
	 */
	@SerializedName("CAFingerprintSHA256")
	private String caFingerprintSHA256;
	/**
	 * The identifier of the issued certificate.
	 */
	@SerializedName("KeyID")
	private String keyID;
	/**
	 * The serial number of the certificate, so consumers will not need to parse it.
	 */
	@SerializedName("SerialNumber")
	private String serialNumber;
	/**
	 * The principals of the issued certificate.
	 */
	@SerializedName("Principals")
	private String[] principals;
	/**
	 * A time in second since 1970-01-01 00:00:00 after the certificate is valid.
	 */
	@SerializedName("ValidFrom")
	private String validFrom;
	/**
	 * A time in second since 1970-01-01 00:00:00 before the certificate is valid.
	 */
	@SerializedName("ValidTo")
	private String validTo;
	/**
	 * The Force Command of the issued certificate.
	 */
	@SerializedName("ForceCommand")
	private String forceCommand;
	/**
	 * The Source Addresses of the issued certificate.
	 */
	@SerializedName("SourceAddresses")
	private String[] sourceAddresses;
	/**
	 * The extensions of the issued certificate.
	 */
	@SerializedName("Extensions")
	private Map<String, String> extensions;
	
}