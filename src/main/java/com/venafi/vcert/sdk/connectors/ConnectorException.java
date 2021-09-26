/**
 * 
 */
package com.venafi.vcert.sdk.connectors;

import static java.lang.String.format;

import java.util.List;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.CsrOriginOption;

/**
 * @author Marcos E. Albornoz Abud
 *
 */
public class ConnectorException extends VCertException {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public ConnectorException(Exception cause) {
		super(cause);
	}

	public ConnectorException(String message, Exception cause) {
		super(message, cause);
	}

	public ConnectorException(String message) {
		super(message);
	}
	
	public static class CloudPingException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		int status;
		String reason;
		
		public CloudPingException(int status, String reason) {
			super(format("Unexpected status code on Venafi Cloud ping. Status: %d %s", status, reason));
			this.status = status;
			this.reason = reason;
		}
	}
	
	public static class TppPingException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		int status;
		String reason;
		
		public TppPingException(int status, String reason) {
			super(format("Ping failed with status %d and reason %s", status, reason));
			this.status = status;
			this.reason = reason;
		}
	}
	
	public static class MissingCredentialsException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public MissingCredentialsException() {
			super("Failed to authenticate: missing credentials");
		}
	}
	
	public static class MissingAccessTokenException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public MissingAccessTokenException() {
			super("Failed to authenticate: missing access token");
		}
	}

	public static class MissingRefreshTokenException extends ConnectorException {

		private static final long serialVersionUID = 1L;

		public MissingRefreshTokenException() {
			super("Failed to authenticate: missing refresh token");
		}
	}
	
	public static class FailedToRevokeTokenException extends ConnectorException {

		private static final long serialVersionUID = 1L;

		public FailedToRevokeTokenException(String message) {
			super(format("Failed to revoke token. Message: %s", message));
		}
	}
	
	public static class ZoneFormatException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public ZoneFormatException(String message) {
			super(message);
		}
	}
	
	public static class TppRequestCertificateNotAllowedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public TppRequestCertificateNotAllowedException() {
			super("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed");
		}
	}
	
	public static class TppManualCSRNotEnabledException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		CsrOriginOption csrOrigin;
		
		public TppManualCSRNotEnabledException(CsrOriginOption csrOrigin) {
			super(format("Unable to request certificate %s CSR when zone configuration is 'Manual Csr' = 0", csrOrigin == CsrOriginOption.LocalGeneratedCSR ? "by local generated" : "with user provided"));
			this.csrOrigin = csrOrigin;
		}
	}
	
	public static class CSRNotProvidedByUserException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CSRNotProvidedByUserException() {
			super("CSR was supposed to be provided by user, but it's empty");
		}
	}
	
	public static class UnreconigzedCSROriginException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		CsrOriginOption csrOrigin;
		
		public UnreconigzedCSROriginException(CsrOriginOption csrOrigin) {
			super(format("Unrecognized request CSR origin %s", csrOrigin));
			this.csrOrigin = csrOrigin;
		}
	}
	
	public static class UnsupportedServiceGeneratedCSRException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UnsupportedServiceGeneratedCSRException() {
			super("Service generated CSR is not supported by Saas service");
		}
	}
	
	public static class UserNotAuthenticatedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UserNotAuthenticatedException(String message) {
			super(message);
		}
	}
	
	public static class UnsupportedPrivateKeyRetrieveException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public UnsupportedPrivateKeyRetrieveException() {
			super("Failed to retrieve private key from Venafi Cloud service: not supported");
		}
	}
	
	public static class CertificateNotFoundByThumbprintException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateNotFoundByThumbprintException(String thumbprint) {
			super(format("No certificate found using thumbprint %s", thumbprint));
		}
	}
	
	public static class MoreThanOneCertificateRequestIdException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		private final static String message = "More than one CertificateRequestId was found with the same thumbprint: %s";
		
		public MoreThanOneCertificateRequestIdException(List<String> reqIds) {
			super(format(message, reqIds));
		}
		
		public MoreThanOneCertificateRequestIdException(String thumbprint) {
			super(format(message, thumbprint));
		}
	}
	
	public static class MoreThanOneCertificateWithSameThumbprintException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		private final static String message = "More than one Certificate was found with the same thumbprint: %s";
		
		String thumbprint;
		
		public MoreThanOneCertificateWithSameThumbprintException(String thumbprint) {
			super(format(message, thumbprint));
			this.thumbprint = thumbprint;
		}
	}
	
	public static class CertificateStatusFailedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateStatusFailedException(String status) {
			super(format("Failed to retrieve certificate. Status: %s", status));
		}
	}
	
	public static class AttemptToRetryException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public AttemptToRetryException( Exception e ) {
			super(format("Error attempting to retry", e));
		}
	}
	
	public static class FailedToRetrieveCertificateStatusException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public FailedToRetrieveCertificateStatusException( String requestId ) {
			super(format("Was not able to retrieve Certificate Status, requestId: %s", requestId));
		}
	}
	
	public static class UnableToReadPEMCertificateException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String certificateId;
		
		public UnableToReadPEMCertificateException(String certificateId) {
			super(format("Unable to read the PEM certificate for certificateID: %s", certificateId));
			this.certificateId = certificateId;
		}
	}
	
	public static class CertificatePendingException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		private static final String message = "Issuance is pending. You may try retrieving the certificate later using Pickup ID: %s";
		
		String pickupId;
		String status;
		
		public CertificatePendingException(String pickupId) {
			super(format(message, pickupId));
			this.pickupId = pickupId;
		}
		
		public CertificatePendingException(String pickupId, String status) {
			super(format(message+"\n\tStatus: %s", pickupId, status));
			this.pickupId = pickupId;
			this.status = status;
		}
	}
	
	public static class RetrieveCertificateTimeoutException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String pickupId;
		
		public RetrieveCertificateTimeoutException(String pickupId) {
			super(format("Operation timed out. You may try retrieving the certificate later using Pickup ID: %s", pickupId));
			this.pickupId = pickupId;
		}
	}
	
	public static class CertificateRejectedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		private static final String message = "Certificate request was rejected. You may need to verify the certificate using Pickup ID: %s";
		
		String pickupId;
		String status;
		
		public CertificateRejectedException(String pickupId) {
			super(format(message, pickupId));
			this.pickupId = pickupId;
		}
		
		public CertificateRejectedException(String pickupId, String status) {
			super(format(message+"\n\tStatus: %s", pickupId, status));
			this.pickupId = pickupId;
			this.status = status;
		}
	}
	
	
	public static class CertificateDNOrThumbprintWasNotProvidedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CertificateDNOrThumbprintWasNotProvidedException() {
			super("Failed to create renewal request: CertificateDN or Thumbprint required");
		}
	}
	
	public static class CSRNotProvidedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CSRNotProvidedException() {
			super("reuseCSR option is not currently available for Renew Certificate operation. "
	    			+ "A new CSR must be provided in the request");
		}
	}
	
	public static class RequestCertificateException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		int errorCode;
		String errorMessage;
		
		public RequestCertificateException(int errorCode, String errorMessage) {
			super(format("Error requesting certificate, error code: %d, error description: %s", errorCode, errorMessage));
			this.errorCode = errorCode;
			this.errorMessage = errorMessage;
		}
	}

	public static class CouldNotParseRevokeReasonException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String reason;
		
		public CouldNotParseRevokeReasonException(String reason) {
			super(format("Could not parse revocation reason `%s`", reason));
			this.reason = reason;
		}
	}
	
	public static class RevokeFailureException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String error;
		
		public RevokeFailureException(String error) {
			super(format("Revocation error: %s", error));
			this.error = error;
		}
	}
	
	public static class RenewFailureException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		String error;
		
		public RenewFailureException(String error) {
			super(format("Certificate renewal error: %", error));
			this.error = error;
		}
	}
	
	public static class CAOrGUIDNotProvidedException extends ConnectorException {
		
		private static final long serialVersionUID = 1L;
		
		public CAOrGUIDNotProvidedException() {
			super("CA template or GUID are not specified");
		}
	}

}
