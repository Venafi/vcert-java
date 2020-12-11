package com.venafi.vcert.sdk.certificate;

import lombok.Data;

@Data
public class CustomField {

	String name;
	String value;

	public CustomField( String name, String value ){

		this.name = name;
		this.value = value;

	} 

}
