/*
 * Copyright 2020 Google LLC
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
 */
package net.oauth.jsontoken;

import static org.junit.Assert.assertThrows;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.SignatureException;
import java.time.Duration;
import java.util.regex.Pattern;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;
import net.oauth.jsontoken.exceptions.ErrorCode;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

public class JsonTokenParserTest extends JsonTokenTestBase {

  public void testVerify_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    parser.verify(checkToken);
  }

  public void testVerify_unsupportedSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    assertThrowsWithErrorCode(
        IllegalArgumentException.class,
        ErrorCode.UNSUPPORTED_ALGORITHM,
        () -> parser.verify(checkToken));
  }

  public void testVerify_noVerifiers() throws Exception {
    VerifierProvider noLocator = (signerId, keyId) -> null;
    VerifierProviders noLocators = new VerifierProviders();
    noLocators.setVerifierProvider(SignatureAlgorithm.HS256, noLocator);

    JsonTokenParser parser = getJsonTokenParser(noLocators, new AlwaysPassChecker());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);

    assertThrowsWithErrorCode(
        IllegalStateException.class, ErrorCode.NO_VERIFIER, () -> parser.verify(checkToken));
  }

  public void testVerify_noProviders() throws Exception {
    VerifierProviders noProviders = new VerifierProviders();
    JsonTokenParser parser = getJsonTokenParser(noProviders, new AlwaysPassChecker());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);

    assertThrows(IllegalArgumentException.class, () -> parser.verify(checkToken));
  }

  public void testVerifyAndDeserialize_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);
    assertHeader(token);
    assertPayload(token);
  }

  public void testVerifyAndDeserialize_deserializeFail() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.MALFORMED_TOKEN_STRING,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_2PARTS));
  }

  public void testVerifyAndDeserialize_verifyFail() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(SignatureException.class, () -> parser.verifyAndDeserialize(TOKEN_STRING_BAD_SIG));
  }

  public void testVerifyAndDeserialize_tokenFromRuby() throws Exception {
    JsonTokenParser parser = getJsonTokenParser(locatorsFromRuby, new AlwaysPassChecker());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY);

    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("JWT", token.getHeader().get(JsonToken.TYPE_HEADER).getAsString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
  }

  public void testPublicKey() throws Exception {
    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setExpiration(clock.now().plus(Duration.ofMillis(60)));

    String tokenString = token.serializeAndSign();

    assertNotNull(token.toString());

    JsonTokenParser parser = getJsonTokenParser();
    token = parser.verifyAndDeserialize(tokenString);
    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());

    // now test what happens if we tamper with the token
    JsonObject payload =
        new JsonParser()
            .parse(
                StringUtils.newStringUtf8(
                    Base64.decodeBase64(tokenString.split(Pattern.quote("."))[1])))
            .getAsJsonObject();
    payload.remove("bar");
    payload.addProperty("bar", 14);
    String payloadString = new Gson().toJson(payload);
    String[] parts = tokenString.split("\\.");
    parts[1] = Base64.encodeBase64URLSafeString(payloadString.getBytes());
    assertEquals(3, parts.length);

    String tamperedToken = parts[0] + "." + parts[1] + "." + parts[2];

    assertThrows(SignatureException.class, () -> parser.verifyAndDeserialize(tamperedToken));
  }

  private JsonTokenParser getJsonTokenParser() {
    return new JsonTokenParser(clock, locators, new AlwaysPassChecker());
  }

  private JsonTokenParser getJsonTokenParser(VerifierProviders providers, Checker... checkers) {
    return new JsonTokenParser(clock, providers, checkers);
  }
}
