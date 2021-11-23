package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import lombok.Data;

@Data
public class KeystoreRequest {
	private String exportFormat;
	private String encryptedPrivateKeyPassphrase;
	private String encryptedKeystorePassphrase;
	private String certificateLabel;
}
