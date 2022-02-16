/**
 * 
 */
package com.venafi.vcert.sdk.certificate;

/**
 * @author Marcos E. Albornoz
 *
 */
public enum DataFormat {
	
	LEGACY("LEGACY"), PKCS8("PKCS#8");
	
	private String id;
	
	DataFormat(String id) {
		this.id = id;
	}

	@Override
	public String toString() {
		return id.toString();
	}

}
