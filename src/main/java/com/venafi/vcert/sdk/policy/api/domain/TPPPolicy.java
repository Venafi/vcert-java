package com.venafi.vcert.sdk.policy.api.domain;

import lombok.*;

@Data
public class TPPPolicy {

    private String policyName;
    private String[] contact;
    private String[] approver;
    private String[] domainSuffixWhiteList;
    private Integer prohibitWildcard;//0, 1
    private String certificateAuthority;
    private AttributeLockable<String> managementType;
    private AttributeLockable<String> organization;
    private AttributeLockable<String> organizationalUnit;
    private AttributeLockable<String> city;
    private AttributeLockable<String> state;
    private AttributeLockable<String> country;
    private AttributeLockable<String> keyAlgorithm;
    private AttributeLockable<String> keyBitStrength;
    private AttributeLockable<String> ellipticCurve;
    private AttributeLockable<String> manualCsr;//0, 1
    private AttributeLockable<String> allowPrivateKeyReuse;//0, 1
    private AttributeLockable<String> wantRenewal;//0, 1
    private String[] prohibitedSANTypes;

    public void managementType(String value, boolean lock){
        managementType(new AttributeLockable(new String[]{value}, lock));
    }

    public void organization(String value, boolean lock){
        organization(new AttributeLockable(new String[]{value}, lock));
    }

    public void organizationalUnit(String[] value, boolean lock){
        organizationalUnit(new AttributeLockable(value, lock));
    }

    public void city(String value, boolean lock){
        city(new AttributeLockable(new String[]{value}, lock));
    }

    public void state(String value, boolean lock){
        state(new AttributeLockable(new String[]{value}, lock));
    }

    public void country(String value, boolean lock){
        country(new AttributeLockable(new String[]{value}, lock));
    }

    public void keyAlgorithm(String value, boolean lock){
        keyAlgorithm(new AttributeLockable(new String[]{value}, lock));
    }

    public void keyBitStrength(String value, boolean lock){
        keyBitStrength(new AttributeLockable(new String[]{value}, lock));
    }

    public void ellipticCurve(String value, boolean lock){
        ellipticCurve(new AttributeLockable(new String[]{value}, lock));
    }

    public void manualCsr(String value, boolean lock){
        manualCsr(new AttributeLockable(new String[]{value}, lock));
    }

    public void allowPrivateKeyReuse(String value, boolean lock){
        allowPrivateKeyReuse(new AttributeLockable(new String[]{value}, lock));
    }

    public void wantRenewal(String value, boolean lock){
        wantRenewal(new AttributeLockable(new String[]{value}, lock));
    }

    public String getParentName(){
        return policyName.substring(0, policyName.lastIndexOf("\\"));
    }
}
