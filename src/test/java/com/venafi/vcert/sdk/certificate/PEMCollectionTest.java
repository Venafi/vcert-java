package com.venafi.vcert.sdk.certificate;

import com.venafi.vcert.sdk.VCertException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

class PEMCollectionTest {

    @Test
    void fromResponse() throws VCertException, IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        String body = new String(Files.readAllBytes(Paths.get(classLoader.getResource("certificates/certWithKey.pem").getPath())));
        PEMCollection pemCollection = PEMCollection.fromResponse(body, ChainOption.ChainOptionIgnore);
        assertThat(pemCollection.certificate()).isNotNull();
        assertThat(pemCollection.chain()).hasSize(0);
        assertThat(pemCollection.privateKey()).isNotNull();
    }
}