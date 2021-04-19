package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import com.venafi.vcert.sdk.connectors.cloud.domain.Application;
import lombok.Data;

import java.util.List;

@Data
public class ApplicationsList {
    private List<Application> applications;
}
