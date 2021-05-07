package com.venafi.vcert.sdk.policy.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SubjectAltNames {

    private Boolean dnsAllowed;
    private Boolean ipAllowed;
    private Boolean emailAllowed;
    private Boolean uriAllowed;
    private Boolean upnAllowed;
}
