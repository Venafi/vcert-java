package com.venafi.vcert.sdk.connectors.cloud.domain;

import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class Application {
	private String id;
	private String companyId;
	private String name;
	private String description;
	private String organizationalUnitId;
	private List<OwnerIdsAndType> ownerIdsAndTypes;
	private List<String> fqDns;
	private List<String> internalFqDns;
	private List<String> externalIpRanges;
	private List<String> internalIpRanges;
	private List<String> internalPorts;
	private Map<String, String> certificateIssuingTemplateAliasIdMap;

	@Data
	public static class OwnerIdsAndType {
		private String ownerId;
		private String ownerType;
	}

}
