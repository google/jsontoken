/**
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package net.oauth.jsontoken;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.SerializedName;

import net.oauth.jsontoken.crypto.SignatureAlgorithm;

import org.joda.time.Duration;
import org.joda.time.Instant;

import java.lang.reflect.Type;

public class Envelope {

  @SerializedName("issuer")
  private String issuer;

  @SerializedName("key_id")
  private String keyId;

  @SerializedName("alg")
  private SignatureAlgorithm algorithm;

  @SerializedName("not_before")
  private Instant notBefore;

  @SerializedName("token_lifetime")
  private Duration tokenLifetime;

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getKeyId() {
    return keyId;
  }

  public void setKeyId(String keyId) {
    this.keyId = keyId;
  }

  public SignatureAlgorithm getSignatureAlgorithm() {
    return algorithm;
  }

  public void setSignatureAlgorithm(SignatureAlgorithm alg) {
    this.algorithm = alg;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Instant notBefore) {
    this.notBefore = notBefore;
  }

  public Duration getTokenLifetime() {
    return tokenLifetime;
  }

  public void setTokenLifetime(Duration tokenLifetime) {
    this.tokenLifetime = tokenLifetime;
  }

  public static Envelope fromJson(String json) {
    return getGson().fromJson(json, Envelope.class);
  }

  public String toJson() {
    return getGson().toJson(this);
  }

  private static Gson getGson() {
    GsonBuilder gson = new GsonBuilder();
    gson.registerTypeAdapter(Instant.class, new InstantEncoder());
    gson.registerTypeAdapter(Duration.class, new DurationEncoder());
    gson.registerTypeAdapter(SignatureAlgorithm.class, new AlgorithmNameEncoder());
    return gson.create();
  }

  private static class InstantEncoder implements JsonSerializer<Instant>, JsonDeserializer<Instant> {
    @Override
    public JsonElement serialize(Instant src, Type typeOfSrc, JsonSerializationContext context) {
      return new JsonPrimitive(src.getMillis());
    }

    @Override
    public Instant deserialize(JsonElement json, Type type, JsonDeserializationContext context)
        throws JsonParseException {
      return new Instant(json.getAsJsonPrimitive().getAsLong());
    }
  }

  private static class DurationEncoder implements JsonSerializer<Duration>, JsonDeserializer<Duration> {
    @Override
    public JsonElement serialize(Duration src, Type typeOfSrc, JsonSerializationContext context) {
      return new JsonPrimitive(src.getMillis());
    }

    @Override
    public Duration deserialize(JsonElement json, Type type, JsonDeserializationContext context)
        throws JsonParseException {
      return new Duration(json.getAsJsonPrimitive().getAsLong());
    }
  }

  private static class AlgorithmNameEncoder implements JsonSerializer<SignatureAlgorithm>, JsonDeserializer<SignatureAlgorithm> {
    @Override
    public JsonElement serialize(SignatureAlgorithm src, Type typeOfSrc, JsonSerializationContext context) {
      return new JsonPrimitive(src.getNameForJson());
    }

    @Override
    public SignatureAlgorithm deserialize(JsonElement json, Type type, JsonDeserializationContext context)
        throws JsonParseException {
      return SignatureAlgorithm.getFromJsonName(json.getAsJsonPrimitive().getAsString());
    }
  }
}
