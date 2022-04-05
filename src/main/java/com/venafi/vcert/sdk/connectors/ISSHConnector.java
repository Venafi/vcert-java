package com.venafi.vcert.sdk.connectors;

import com.venafi.vcert.sdk.VCertException;
import com.venafi.vcert.sdk.certificate.SshCaTemplateRequest;
import com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails;
import com.venafi.vcert.sdk.certificate.SshCertificateRequest;
import com.venafi.vcert.sdk.certificate.SshConfig;

public interface ISSHConnector {

    /**
     * Request a new SSH Certificate.
     * @param sshCertificateRequest The {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest} instance needed to do the request.
     * For more information about of which properties should be filled, please review the documentation of
     * {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest}.
     * @return The DN of the created SSH certificate object. It can be used as pickup ID to retrieve the created SSH Certificate.
     * For more details review the {@link #retrieveSshCertificate(SshCertificateRequest) retrieveSshCertificate(SshCertificateRequest)} method.
     * @throws VCertException
     */
    String requestSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException;

    /**
     * Retrieve a requested SSH Certificate
     * @param sshCertificateRequest The {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest} instance needed to do the request.
     * <br>It's mandatory to set the PickUpID which is the value of the DN returned when the SSH Certificate was requested.
     * For more information about of which properties should be filled, please review the documentation of
     * {@link com.venafi.vcert.sdk.certificate.SshCertificateRequest SshCertificateRequest}.
     * @return A {@link com.venafi.vcert.sdk.certificate.SshCertRetrieveDetails SshCertRetrieveDetails} containing the Certificate Data of the created Certificate.
     * @throws VCertException
     */
    SshCertRetrieveDetails retrieveSshCertificate(SshCertificateRequest sshCertificateRequest) throws VCertException;

    /**
     * Retrieve the {@link com.venafi.vcert.sdk.certificate.SshConfig SshConfig} of the CA specified in the
     * {@link com.venafi.vcert.sdk.certificate.SshCaTemplateRequest SshCaTemplateRequest}.
     * @param sshCaTemplateRequest
     * @return A {@link com.venafi.vcert.sdk.certificate.SshConfig SshConfig}.
     * @throws VCertException
     */
    SshConfig retrieveSshConfig(SshCaTemplateRequest sshCaTemplateRequest) throws VCertException;
}
