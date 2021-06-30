/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import static java.lang.String.format;

import java.util.List;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class CloudConnectorException extends VCertException {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CloudConnectorException(Exception cause) {
		super(cause);
	}

	public CloudConnectorException(String message, Exception cause) {
		super(message, cause);
	}

	public CloudConnectorException(String message) {
		super(message);
	}
	
	public static class UnexpectedStatusException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		int status;
		String reason;
		
		public UnexpectedStatusException(int status, String reason) {
			super(format("Unexpected status code on Venafi Cloud ping. Status: %d %s", status, reason));
			this.status = status;
			this.reason = reason;
		}
	}
	
	public static class ZoneFormatException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public ZoneFormatException(String message) {
			super(message);
		}
	}
	
	public static class CSRNotProvidedByUserException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CSRNotProvidedByUserException() {
			super("CSR was supposed to be provided by user, but it's empty");
		}
	}
	
	public static class UnreconigzedCSROriginException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		CsrOriginOption csrOrigin;
		
		public UnreconigzedCSROriginException(CsrOriginOption csrOrigin) {
			super(format("Unrecognized request CSR origin %s", csrOrigin));
			this.csrOrigin = csrOrigin;
		}
	}
	
	public static class UnsupportedServiceGeneratedCSRException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UnsupportedServiceGeneratedCSRException() {
			super("Service generated CSR is not supported by Saas service");
		}
	}
	
	public static class UserNotAuthenticatedException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UserNotAuthenticatedException(String message) {
			super(message);
		}
	}
	
	public static class UnsupportedPrivateKeyRetrieveException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UnsupportedPrivateKeyRetrieveException() {
			super("Failed to retrieve private key from Venafi Cloud service: not supported");
		}
	}
	
	public static class CertificateNotFoundByFingerprintException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateNotFoundByFingerprintException(String fingerprint) {
			super(format("No certificate found using fingerprint %s", fingerprint));
		}
	}
	
	public static class MoreThanOneCertificateRequestIdException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		private final static String message = "More than one CertificateRequestId was found with the same Fingerprint: %s";
		
		public MoreThanOneCertificateRequestIdException(List<String> reqIds) {
			super(format(message, reqIds));
		}
		
		public MoreThanOneCertificateRequestIdException(String fingerprint) {
			super(format(message, fingerprint));
		}
	}
	
	public static class CertificateStatusFailedException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateStatusFailedException(String status) {
			super(format("Failed to retrieve certificate. Status: %s", status));
		}
	}
	
	public static class AttemptToRetryException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public AttemptToRetryException( Exception e ) {
			super(format("Error attempting to retry", e));
		}
	}
	
	public static class FailedToRetrieveCertificateStatusException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public FailedToRetrieveCertificateStatusException( String requestId ) {
			super(format("Was not able to retrieve Certificate Status, requestId: %s", requestId));
		}
	}
	
	public static class UnableToReadPEMCertificateException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String certificateId;
		
		public UnableToReadPEMCertificateException(String certificateId) {
			super(format("Unable to read the PEM certificate for certificateID: %s", certificateId));
			this.certificateId = certificateId;
		}
	}
	
	public static class CertificatePendingException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String pickupId;
		
		public CertificatePendingException(String pickupId) {
			super(format("Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s", pickupId));
			this.pickupId = pickupId;
		}
	}
	
	public static class RetrieveCertificateTimeoutException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String pickupId;
		
		public RetrieveCertificateTimeoutException(String pickupId) {
			super(format("Operation timed out. You may try retrieving the certificate later using Pickup ID: %s", pickupId));
			this.pickupId = pickupId;
		}
	}
	
	public static class CertificateDNOrFingerprintWasNotProvidedException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateDNOrFingerprintWasNotProvidedException() {
			super("Failed to create renewal request: CertificateDN or Thumbprint required");
		}
	}
	
	public static class CSRNotProvidedException extends CloudConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CSRNotProvidedException() {
			super("reuseCSR option is not currently available for Renew Certificate operation. "
	    			+ "A new CSR must be provided in the request");
		}
	}

}
