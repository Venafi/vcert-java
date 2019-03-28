package com.venafi.vcert.sdk.utils;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.venafi.vcert.sdk.connectors.tpp.Tpp;
import feign.Feign;
import feign.Logger;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;

import java.lang.reflect.Type;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FeignUtils {

    static Supplier<GsonBuilder> gsonBuilderFactory = GsonBuilder::new;

    public static <T> T client(Class<T> clazz, String baseUrl) {
        GsonBuilder builder = gsonBuilderFor(clazz);
        return Feign.builder()
                .encoder(encoder(builder))
                .decoder(decoder(builder))
                .logger(new Slf4jLogger())
                .logLevel(Logger.Level.FULL)
                .target(clazz, baseUrl);
    }

    private static <T> GsonBuilder gsonBuilderFor(Class<T> clazz) {
        GsonBuilder builder = gsonBuilderFactory.get();
        if (Tpp.class.equals(clazz)) {
            builder.setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE);
        }
        return builder;
    }


    private static GsonDecoder decoder(GsonBuilder builder) {
        return new GsonDecoder(builder
                .registerTypeAdapter(OffsetDateTime.class, new MicrosoftJsonDateFormatDeserializer())
                .create());
    }

    private static GsonEncoder encoder(GsonBuilder builder) {
        return new GsonEncoder(builder.create());
    }

    /**
     * @see <a href="https://web.archive.org/web/20080119145729/http://weblogs.asp.net/bleroy/archive/2008/01/18/dates-and-json.aspx">origin story</a>
     */
    private static class MicrosoftJsonDateFormatDeserializer implements JsonDeserializer<OffsetDateTime> {

        static final Pattern msDate = Pattern.compile("^/Date\\((?<epoch>\\d+)(?<offset>(?:[+-]\\d+|Z))?\\)/$");
        static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");


        @Override
        public OffsetDateTime deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            if (json.isJsonNull() || json.getAsString().isEmpty()) {
                throw new JsonParseException(String.format("Unable to parse ZonedDateTime from [ %s ].", json.toString()));
            }
            String dateString = json.getAsString();
            Matcher input = msDate.matcher(dateString);
            if (!input.matches()) {
                return OffsetDateTime.parse(dateString, formatter);
            }
            // There is apocryphal, anecdotal evidence that the format can have an offset, although the original blog
            // post doesn't seem to mention it - and it would, indeed, be counterproductive, as the JavaScript Date()
            // constructor doesn't accept epoch with offset as an argument - but we can't rule out the existence
            // of such time stamps in the wild, so we support them.
            if (input.group("offset") != null) {
                return OffsetDateTime
                        .from(Instant.ofEpochMilli(Long.parseLong(input.group("epoch"))))
                        .withOffsetSameInstant(ZoneOffset.of(input.group("offset")));
            }
            return OffsetDateTime
                    .from(Instant
                            .ofEpochMilli(Long.parseLong(input.group("epoch")))
                            .atZone(ZoneOffset.UTC));
        }
    }
}