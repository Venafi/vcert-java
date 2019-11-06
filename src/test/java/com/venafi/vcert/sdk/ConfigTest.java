package com.venafi.vcert.sdk;


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ConfigTest {

  @Test
  @DisplayName("Configuration file for TPP")
  void loadConfigurationFileForTpp() throws URISyntaxException, VCertException {
    final Config config = Config.loadConfigFromFile(getFilePath("validTPPConfig.ini"));

    assertThat(config.baseUrl()).isEqualTo("https://ha-tpp1.example.com:5008/vedsdk");
    assertThat(config.credentials().user()).isEqualTo("admin");
    assertThat(config.credentials().password()).isEqualTo("xxx");
    assertThat(config.zone()).isEqualTo("devops\\vcert");
  }

  @Test
  @DisplayName("Invalid configuration missing password")
  void loadConfigurationFileForTppMissingPassword() {
    Throwable throwable = assertThrows(VCertException.class,
        () -> Config.loadConfigFromFile(getFilePath("invalidTPPMissingPassword.ini")));

    assertThat(throwable.getMessage()).contains("missing TPP password");
  }

  @Test
  @DisplayName("Load valid cloud configuration")
  void loadConfigurationFileForCloud() throws URISyntaxException, VCertException {
    final Config config = Config.loadConfigFromFile(getFilePath("validCloudConfig.ini"));

    assertThat(config.baseUrl()).isEqualTo("https://api.dev12.qa.venafi.io/v1");
    assertThat(config.credentials().apiKey()).isEqualTo("xxxxxxxx-b256-4c43-a4d4-15372ce2d548");
    assertThat(config.zone()).isEqualTo("Default");
  }

  @Test
  @DisplayName("Load an invalid cloud configuration")
  void loadConfigurationInvalidFileForCloud() {
    Throwable throwable = assertThrows(VCertException.class,
        () -> Config.loadConfigFromFile(getFilePath("invalidCloudConfig.ini")));
    assertThat(throwable.getMessage()).contains("illegal key tpp_user in section");
  }

  @Test
  @DisplayName("Empty config file is not accepted")
  void emptyConfigFile() {
    Throwable throwable = assertThrows(VCertException.class,
        () -> Config.loadConfigFromFile(getFilePath("emptyConfig.ini")));
    assertThat(throwable.getMessage()).contains("The configuration file is empty");
  }

  @Test
  @DisplayName("Invalid configuration file")
  void invalidConfigFile() {
    Throwable throwable = assertThrows(VCertException.class,
        () -> Config.loadConfigFromFile(getFilePath("invalidConfig.ini")));
    assertThat(throwable.getMessage()).contains("requires 'tpp_url' or 'cloud_apikey'");
  }

  private Path getFilePath(String resourceName) throws URISyntaxException {
    return Paths.get(this.getClass().getClassLoader().getResource(resourceName).toURI());
  }

}
