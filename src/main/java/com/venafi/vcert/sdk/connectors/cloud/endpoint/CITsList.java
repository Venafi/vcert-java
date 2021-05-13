package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import com.venafi.vcert.sdk.connectors.cloud.domain.CertificateIssuingTemplate;
import lombok.Data;

import java.util.List;

@Data
public class CITsList {
    private List<CertificateIssuingTemplate> certificateIssuingTemplates;
}
