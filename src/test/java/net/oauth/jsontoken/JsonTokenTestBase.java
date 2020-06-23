/**
 * Copyright 2010 Google LLC
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

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URI;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.regex.Pattern;
import junit.framework.TestCase;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.*;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

public abstract class JsonTokenTestBase extends TestCase {

  protected static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();

  protected static final String PRIVATE_KEY =
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6nMEXFuxTnM5+yM4Afngybf5Z" +
      "89JxlchBA3Ni//Gm1/25MetzfId2Jg8NkthmRDzH6sFaoNS7n6Z6JyNJFszb2PXKBkZdem219F5k" +
      "jawoHrfA1Lu8fBmGQYG/aG70aPft2eEZbY+XqW5WUlMk7vFW7BDikwBXyv/5rrFasBfPWd13xozQ" +
      "9612IErWGlGMgxmB64jcTbGWMzDgzE/scSmyeQ0vQQMW8J+Nnb/yDpY7loXrVrAgZx8IBv1f9Fv3" +
      "p7tirTD/vFgzxE2rIAauM/aU8zBHEyXL1NSNq0I62OAF4DLiDlcEFOvYjqoiCPQIh0NXnQy8Dcs5" +
      "xHCj0e1b3X/LAgMBAAECggEBAJ9G5iQQA7xF7ZYXTITtbSgV6+/ZBTi/kEG1cUoBjL9MQZpNOlrC" +
      "4lf8mgKK4LtA6OP1wfzZo1lVJeHDAAIFPOs0nm1Ft89XjMauAdcveM5xkYM7z9VL0vlddiHqQDHK" +
      "WjsgKVnrwpC/I5b4A1FVxJXdPXg14igM8zioW2Y9QMVPxeUmRJxeGfvlotRlD1At1KNKg7Q2bPoi" +
      "1IlRzdae6ky18x/o6FRbTo2WGRehqIAjqmwqNib3u4k/1QfEbKGShVjMtraxdlFBM7kXb/pTfhhU" +
      "xlsf4xraVy2LWBLen+BAOYScd0P7vD+5oET+e4YVqILoz/WQqI9BYmTHkzj+LLECgYEA9bVjRrXq" +
      "5NtO94w0T2BI9yGnZNRFbCcSocUlc6lgX7lFa6N5JvaoWF5p9CmUPPm7lxGOeSzvLKB4qv3uP/Px" +
      "RQzWvAT/isKnSJ2FuKcFYGA527uJ5BlOJAtTKViYhQdYlE2g9KsjLkxJ27aF49jrkhKWqueIdJpF" +
      "VfF9w+KYvVkCgYEAwm205fCRH3WEBzii2TrHqm/nVRWZ7Kxis4JppwxUslLKp33bzbHn9uOKFGfN" +
      "rtXpSq9hvAcnJlJAEyVFtVNFcazE/+GbUfnrKaC3UeomjYxBk45Lcutt441gOO2SFcra7GHiNgVv" +
      "fELNMo/Rr7tk8djcUcYXuDk4Kz/T2AttzcMCgYBg/Z8YtIrqmB+N3Exx4OIsm55GUPyueqYCMZ5d" +
      "D8k5QBtFKByU4t0FNQ/CD/+yKiqAsa956eDnztiTNvWrTRI6XZ0OTzLIhZofMf8tKtEWgCWWtWrz" +
      "HYIY/FdxhMWADaxLrnEQ49VZW0f0cRJdJK2o1amgARF+Zb9k85TflD0S0QKBgBYFlQrCT72vcs/a" +
      "k19lb/4XBK23b6LF97v7VnosRF+aTwffkoje0LY/GYGsLDjUU8M40Coa6U1G3akNfLLIBsKUXg/Z" +
      "ft0vIHqrkHf/vHQl4buTz2npzp2Kgs6P4g8D1f4WLCgQP4tkiZdjgM2VvR5DgNjmRgOAv6LubNE4" +
      "oiw/AoGAXKfOSrbgx8JQUE7Lt6mhGvP9oTj3uiV16GgxjOtkpP3TfjsdRcmivAuekKMMKufQvGxh" +
      "nX9eCYvLqJqZZwPy/002H7So3Yd1/d9ORkKetDKGjXHPDYyEPQQ+ss9OGm53XlViklXb+i9wsdDz" +
      "R7tAFexSjyVKnWSDBh52t6lBtHo=";

  private static final String SERVER_INFO_DOCUMENT = "{ \"verification_keys\": {" +
      // this is the public key that goes with the above private key
      "\"key1\":\"RSA.ALqcwRcW7FOczn7IzgB-eDJt_lnz0nGVyEEDc2L_8abX_bkx63N8h3YmDw2S2GZEPMfqwVqg1LufpnonI0kWzNvY9coGRl16bbX0XmSNrCget8DUu7x8GYZBgb9obvRo9-3Z4Rltj5epblZSUyTu8VbsEOKTAFfK__musVqwF89Z3XfGjND3rXYgStYaUYyDGYHriNxNsZYzMODMT-xxKbJ5DS9BAxbwn42dv_IOljuWhetWsCBnHwgG_V_0W_enu2KtMP-8WDPETasgBq4z9pTzMEcTJcvU1I2rQjrY4AXgMuIOVwQU69iOqiII9AiHQ1edDLwNyznEcKPR7Vvdf8s.AQAB\"" +
      "}, " +
      // some other information that might be in the server info document.
      "\"foo\": \"bar\"}";

  protected VerifierProviders locators;
  protected VerifierProviders locatorsFromRuby;
  protected RSAPrivateKey privateKey;

  protected static final String TOKEN_STRING = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Xugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  protected static final String TOKEN_STRING_BAD_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Wugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  protected static final String TOKEN_STRING_CORRUPT_PAYLOAD = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3&&&&&nb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Xugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  protected static final String TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM = "eyJhbGciOiJIUzUxMiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.44qsiZg1Hnf95N-2wNqd1htgDlE7X0BSUMMkboMcZ5QLKbmVATozMuzdoE0MAhU-IdWUuICFbzu_wcDEXDTLug";
  protected static final String TOKEN_FROM_RUBY = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8";

  protected static final Duration SKEW = Duration.standardMinutes(1);
  protected FakeClock clock = new FakeClock(SKEW);

  /**
   * Convert encoded tokens into a more human-readable form without verifying.
   * Useful for logging.
   */
  protected static String decodeTokenForHumans(String encodedToken) {
    String[] pieces = encodedToken.split(Pattern.quote("."));
    if (pieces.length != 3) {
      return "invalid token (3 segments expected): " + encodedToken;
    }
    for (int i = 0; i < 3; i++) {
      pieces[i] = new String(Base64.decodeBase64(pieces[i].getBytes()));
    }
    return pieces[0] + "." + pieces[1] + "." + pieces[2];
  }

  @Override
  protected void setUp() throws Exception {
    final Verifier hmacVerifier = new HmacSHA256Verifier(SYMMETRIC_KEY);

    VerifierProvider hmacLocator = new VerifierProvider() {
      @Override
      public List<Verifier> findVerifier(String signerId, String keyId) {
        return Lists.newArrayList(hmacVerifier);
      }
    };

    VerifierProvider rsaLocator = new DefaultPublicKeyLocator(
        new IdentityServerDescriptorProvider(),
        new ServerInfoResolver() {
          @Override
          public ServerInfo resolve(URI uri) {
            return JsonServerInfo.getDocument(SERVER_INFO_DOCUMENT);
          }
        });

    locators = new VerifierProviders();
    locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
    locators.setVerifierProvider(SignatureAlgorithm.RS256, rsaLocator);

    EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(PRIVATE_KEY));
    KeyFactory fac = KeyFactory.getInstance("RSA");
    privateKey = (RSAPrivateKey) fac.generatePrivate(spec);


    //final Verifier hmacVerifierFromRuby = new HmacSHA256Verifier("R9bPJ_QRlcgK_hDLgu1Klg".getBytes());
    final Verifier hmacVerifierFromRuby = new HmacSHA256Verifier("secret".getBytes());
    VerifierProvider hmacLocatorFromRuby = new VerifierProvider() {
      @Override
      public List<Verifier> findVerifier(String signerId, String keyId) {
        return Lists.newArrayList(hmacVerifierFromRuby);
      }
    };
    locatorsFromRuby = new VerifierProviders();
    locatorsFromRuby.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocatorFromRuby);

    clock.setNow(new Instant(1276669722000L));
  }

  protected void assertHeader(JsonToken token) {
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
  }

  protected void assertPayload(JsonToken token) {
    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669723000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  /**
   * Deserializes the token string such that tokenStrings without signatures are allowed.
   * Only supports token strings with at least two parts.
   */
  protected JsonToken naiveDeserialize(String tokenString) {
    List<String> pieces = Splitter.on(JsonTokenUtil.DELIMITER).splitToList(tokenString);
    JsonParser jsonParser = new JsonParser();
    JsonObject header = jsonParser.parse(JsonTokenUtil.fromBase64ToJsonString(pieces.get(0))).getAsJsonObject();
    JsonObject payload = jsonParser.parse(JsonTokenUtil.fromBase64ToJsonString(pieces.get(1))).getAsJsonObject();
    return new JsonToken(header, payload, clock, tokenString);
  }
}
