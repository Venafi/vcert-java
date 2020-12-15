package com.venafi.vcert.sdk.connectors.tpp;

import java.util.Collection;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class CustomFieldRequest {
	@SerializedName("Name")
	private String name;
	@SerializedName("Values")
	private Collection<String> values;
}