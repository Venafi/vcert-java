package com.venafi.vcert.sdk;

import static java.util.Arrays.asList;
import java.io.IOException;
import java.net.Proxy;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import org.ini4j.Profile;
import org.ini4j.Wini;
import feign.Client;
import lombok.Builder;
import lombok.Data;
import com.venafi.vcert.sdk.endpoint.Authentication;
import com.venafi.vcert.sdk.endpoint.ConnectorType;

@Data
@Builder
public class Config {
  public static final String DEFAULT_SECTION = "?";
  public static final List<String> VALID_TPP_KEYS = asList("tpp_url", "tpp_user", "tpp_password",
      "tpp_zone", "trust_bundle", "product_name_and_version");

  public static final List<String> VALID_CLOUD_KEYS = asList("cloud_url", "cloud_apikey",
      "cloud_zone", "trust_bundle", "cloud_project", "vendor_name_and_version");

  private ConnectorType connectorType;
  private String baseUrl;
  private String project;
  private String zone;
  private Authentication credentials;
  private String connectionTrust;
  private boolean logVerbose;
  private String configFile;
  private String configSection;
  private String productNameAndVersion;
  private Proxy proxy;
  private String proxyUser;
  private String proxyPassword;
  private Client client;


  public static Config loadConfigFromFile(Path path) throws VCertException {
    final ConfigBuilder builder = Config.builder();
    final Authentication.AuthenticationBuilder authBuilder = Authentication.builder();

    try {
      final Wini ini = new Wini(path.toFile());
      final Profile.Section defaultSection = ini.get(DEFAULT_SECTION);
      validateConfigFile(defaultSection);

      if (defaultSection.containsKey("tpp_url")) {
        builder.connectorType(ConnectorType.TPP);
        builder.baseUrl(defaultSection.get("tpp_url"));
        authBuilder.user(defaultSection.get("tpp_user"));
        authBuilder.password(defaultSection.get("tpp_password"));

        if (defaultSection.containsKey("tpp_zone")) {
          builder.zone(defaultSection.get("tpp_zone"));
        }
      } else if (defaultSection.containsKey("cloud_apikey")) {
        authBuilder.apiKey(defaultSection.get("cloud_apikey"));
        if (defaultSection.containsKey("cloud_url")) {
          builder.baseUrl(defaultSection.get("cloud_url"));
        }

        if (defaultSection.containsKey("cloud_zone")) {
          builder.zone(defaultSection.get("cloud_zone"));
        }

        if (defaultSection.containsKey("cloud_project")) {
          builder.project(defaultSection.get("cloud_project"));
        }
      }

      if (defaultSection.containsKey("product_name_and_version")) {
        builder.productNameAndVersion(defaultSection.get("product_name_and_version"));
      }

      builder.credentials(authBuilder.build());
      return builder.build();
    } catch (IOException e) {
      throw new VCertException(
          String.format("Access error to the configuration file: %s", path.toString()));
    }
  }

  private static void validateConfigFile(Profile.Section defaultSection) throws VCertException {
    if (Objects.isNull(defaultSection)) {
      throw new VCertException("The configuration file is empty");
    }

    if (defaultSection.containsKey("tpp_url")) {
      for (String key : defaultSection.keySet()) {
        if (!VALID_TPP_KEYS.contains(key)) {
          throw new VCertException(
              String.format("illegal key %s in section %s", key, defaultSection.getName()));
        }
      }
      if (!defaultSection.containsKey("tpp_user")) {
        throw new VCertException(String.format("configuration issue section %s: missing TPP user",
            defaultSection.getName()));
      }
      if (!defaultSection.containsKey("tpp_password")) {
        throw new VCertException(String.format(
            "configuration issue section %s: missing TPP password", defaultSection.getName()));
      }
    } else if (defaultSection.containsKey("cloud_apikey")) {
      for (String key : defaultSection.keySet()) {
        if (!VALID_CLOUD_KEYS.contains(key)) {
          throw new VCertException(
              String.format("illegal key %s in section %s", key, defaultSection.getName()));
        }
      }
    } else {
      throw new VCertException(String.format("Section %s requires 'tpp_url' or 'cloud_apikey'",
          defaultSection.getName()));
    }
  }
}
