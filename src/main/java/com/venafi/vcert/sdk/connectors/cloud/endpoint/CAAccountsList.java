package com.venafi.vcert.sdk.connectors.cloud.endpoint;

import lombok.Data;

import java.util.List;

@Data
public class CAAccountsList {
    private List<CAAccount> accounts;

}
