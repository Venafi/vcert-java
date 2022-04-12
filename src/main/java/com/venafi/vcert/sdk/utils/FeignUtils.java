package com.venafi.vcert.sdk.utils;

import java.lang.reflect.Type;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.venafi.vcert.sdk.connectors.tpp.TppToken;
import feign.Client;
import feign.Feign;
import feign.Logger;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import com.venafi.vcert.sdk.Config;
import com.venafi.vcert.sdk.connectors.tpp.Tpp;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class FeignUtils {

  static Supplier<GsonBuilder> gsonBuilderFactory = GsonBuilder::new;

  public static <T> T client(Class<T> clazz, Config config) {
    GsonBuilder builder = gsonBuilderFor(clazz);
    Client client = config.client();

    if (client == null) {
      if (config.proxy() == null) {
        client = new Client.Default(getSSLSocketFactory(), null);
      } else {
        if (config.proxyUser() != null && config.proxyPassword() != null) {
          client = new Client.Proxied(null, null, config.proxy(), config.proxyUser(),
              config.proxyPassword());
        } else {
          client = new Client.Proxied(null, null, config.proxy());
        }
      }
    }
    return Feign.builder().client(client).encoder(encoder(builder)).decoder(decoder(builder))
        .logger(new Slf4jLogger()).logLevel(Logger.Level.BASIC).target(clazz, config.baseUrl());
  }

  private static <T> GsonBuilder gsonBuilderFor(Class<T> clazz) {
    GsonBuilder builder = gsonBuilderFactory.get();
    if (Tpp.class.equals(clazz) || TppToken.class.equals(clazz)) {
      builder.setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE);
    }
    return builder;
  }


  private static GsonDecoder decoder(GsonBuilder builder) {
    return new GsonDecoder(
        builder.registerTypeAdapter(OffsetDateTime.class, new MicrosoftJsonDateFormatDeserializer())
            .create());
  }

  private static GsonEncoder encoder(GsonBuilder builder) {
    return new GsonEncoder(builder.create());
  }

  private static SSLSocketFactory getSSLSocketFactory() {
    try {
      if(isDebugMode()){
        SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        return sslContext.getSocketFactory();
      }  else{
          return null;
      }
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  public static boolean isDebugMode(){
    boolean debug = false;

    String value = System.getenv("DEBUG");
    if(value != null && !value.isEmpty() & !value.equals("")){
      debug = true;
    }

    return debug;
  }

  /**
   * @see <a href=
   *      "https://web.archive.org/web/20080119145729/http://weblogs.asp.net/bleroy/archive/2008/01/18/dates-and-json.aspx">origin
   *      story</a>
   */
  private static class MicrosoftJsonDateFormatDeserializer
      implements JsonDeserializer<OffsetDateTime> {

    static final Pattern msDate =
        Pattern.compile("^/Date\\((?<epoch>\\d+)(?<offset>(?:[+-]\\d+|Z))?\\)/$");
    static final DateTimeFormatter formatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");


    @Override
    public OffsetDateTime deserialize(JsonElement json, Type typeOfT,
        JsonDeserializationContext context) throws JsonParseException {
      if (json.isJsonNull() || json.getAsString().isEmpty()) {
        throw new JsonParseException(
            String.format("Unable to parse ZonedDateTime from [ %s ].", json.toString()));
      }
      String dateString = json.getAsString();
      Matcher input = msDate.matcher(dateString);
      if (!input.matches()) {
    	  try {
    		  return OffsetDateTime.parse(dateString, formatter);
    	  } catch (Exception e) {
    		  return OffsetDateTime.parse(dateString, DateTimeFormatter.ISO_DATE_TIME);
		}
      }
      
      // There is apocryphal, anecdotal evidence that the format can have an offset,
      // although the original blog post doesn't seem to mention it - and it would, indeed, be
      // counterproductive, as the JavaScript Date() constructor doesn't accept epoch with offset as
      // an argument - but we can't rule out the existence of such time stamps in the wild, so we
      // support them.
      if (input.group("offset") != null) {
        return OffsetDateTime.from(Instant.ofEpochMilli(Long.parseLong(input.group("epoch"))))
            .withOffsetSameInstant(ZoneOffset.of(input.group("offset")));
      }
      return OffsetDateTime
          .from(Instant.ofEpochMilli(Long.parseLong(input.group("epoch"))).atZone(ZoneOffset.UTC));
    }
  }
}
