package com.venafi.vcert.sdk.utils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import com.venafi.vcert.sdk.certificate.CertificateRequest;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.CertificateRequestsPayload;
import com.venafi.vcert.sdk.connectors.tpp.AbstractTppConnector.NameValuePair;

public class VCertUtils {

	public static void addExpirationDateAttribute( CertificateRequest request, CertificateRequestsPayload payload ) {

		if ( request.validityHours() > 0 ) {

			Instant now = Instant.now();
			LocalDateTime utcTime = LocalDateTime.ofInstant(now, ZoneOffset.UTC);

			int validityDays = getValidityDays(request.validityHours());

			utcTime = utcTime.plusDays( validityDays );
			String expirationDate = DateTimeFormatter.ofPattern( "yyyy-MM-dd HH:mm:ss" ).format( utcTime );

			// determine issuer hint.

			String issuerHint = "";
			String expirationDateAttribute = "";

			if ( request.issuerHint() != null) {

				issuerHint = String.valueOf( request.issuerHint().charAt(0) );
				issuerHint = issuerHint.toUpperCase();

			}

			switch ( issuerHint ) {

			case "M":
				expirationDateAttribute = "Microsoft CA:Specific End Date";
				break;

			case "D":
				expirationDateAttribute = "DigiCert CA:Specific End Date";
				break;

			case "E":
				expirationDateAttribute = "EntrustNET CA:Specific End Date";
				break;

			default:
				expirationDateAttribute = "Specific End Date";
				break;
			}

			payload.caSpecificAttributes()
			.add( new NameValuePair<String, String>(expirationDateAttribute, expirationDate) );
		}

	}

	public static int getValidityDays( int validityHours ) {

		int validityDays = validityHours / 24;

		//If dividing the hours to convert them to days have fractional numbers then round it
		//to the next day.
		if ( validityHours % 24 > 0 ) {

			validityDays = validityDays + 1;

		}

		return validityDays;
	}

}
