package com.venafi.vcert.sdk.policyspecification.domain;

import lombok.Data;

@Data
public class SubjectAltNames {

    private Boolean dnsAllowed;
    private Boolean ipAllowed;
    private Boolean emailAllowed;
    private Boolean uriAllowed;
    private Boolean upnAllowed;
}
