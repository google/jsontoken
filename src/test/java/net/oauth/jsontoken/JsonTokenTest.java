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

import junit.framework.TestCase;

import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.DefaultPublickeyLocator;
import net.oauth.jsontoken.discovery.IdentityServerDescriptorProvider;
import net.oauth.jsontoken.discovery.JsonServerInfo;
import net.oauth.jsontoken.discovery.ServerInfo;
import net.oauth.jsontoken.discovery.ServerInfoResolver;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.net.URI;
import java.security.KeyFactory;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class JsonTokenTest extends TestCase {

  private static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();

  private static final String PRIVATE_KEY =
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
      "}}";

  private VerifierProviders locators;

  @Override
  protected void setUp() throws Exception {
    final HmacSHA256Verifier hmacVerifier = new HmacSHA256Verifier(SYMMETRIC_KEY);

    VerifierProvider hmacLocator = new VerifierProvider() {
      @Override
      public Verifier findVerifier(String signerId, String keyId) {
        return hmacVerifier;
      }
    };

    VerifierProvider rsaLocator = new DefaultPublickeyLocator(
        new IdentityServerDescriptorProvider(),
        new ServerInfoResolver() {
          @Override
          public ServerInfo resolve(URI uri) {
            return JsonServerInfo.getDocument(SERVER_INFO_DOCUMENT);
          }
        });

    locators = new VerifierProviders();
    locators.setKeyLocator(SignatureAlgorithm.HMAC_SHA256, hmacLocator);
    locators.setKeyLocator(SignatureAlgorithm.RSA_SHA256, rsaLocator);
  }

  public void testSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");

    JsonTokenBuilder<SamplePayload> builder = JsonTokenBuilder.newBuilder();
    JsonToken<SamplePayload> token = builder
        .setDuration(Duration.standardMinutes(1))
        .setNotBefore(new Instant())
        .setSigner(signer)
        .create(payload);

    System.out.println(token.toString());
    System.out.println(token.getToken());

    assertNotNull(token.toString());
  }

  public void testVerification() throws Exception {
    String tokenString = "eyJmb28iOiJzb21lIHZhbHVlIiwiYmFyIjoxNX0.eyJpc3N1ZXIiOiJnb29nbGUuY29tIiwia2V5X2lkIjoia2V5MiIsImFsZyI6IkhNQUMtU0hBMjU2Iiwibm90X2JlZm9yZSI6MTI3NjIzMzg4NjMwMiwidG9rZW5fbGlmZXRpbWUiOjYwMDAwfQ.9pupBctiHO3oFigwYCDahexJT7U6sckf-oQVQeUiqhk";
    PayloadDeserializer<SamplePayload> deserializer =
        DefaultPayloadDeserializer.newDeserializer(SamplePayload.class);

    FakeClock clock = new FakeClock();
    clock.setNow(new Instant(1276233887000L));
    JsonTokenParser parser = new JsonTokenParser(clock, locators);
    JsonToken<SamplePayload> token = parser.parseToken(tokenString, deserializer);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());
  }

  public void testPublicKey() throws Exception {

    EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(PRIVATE_KEY));
    KeyFactory fac = KeyFactory.getInstance("RSA");
    RSAPrivateKey key = (RSAPrivateKey) fac.generatePrivate(spec);


    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", key);

    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");

    JsonTokenBuilder<SamplePayload> builder = JsonTokenBuilder.newBuilder();
    JsonToken<SamplePayload> token = builder
        .setDuration(Duration.standardMinutes(1))
        .setNotBefore(new Instant())
        .setSigner(signer)
        .create(payload);

    String tokenString = token.getToken();

    System.out.println(token.toString());
    System.out.println(tokenString);

    assertNotNull(token.toString());

    PayloadDeserializer<SamplePayload> deserializer =
        DefaultPayloadDeserializer.newDeserializer(SamplePayload.class);
    JsonTokenParser parser = new JsonTokenParser(locators);
    token = parser.parseToken(tokenString, deserializer);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());

    // now test what happens if we tamper with the token
    payload.setBar(14);
    String payloadString = payload.toJson();
    String tamperedToken = tokenString.replaceFirst("[^.]+", Base64.encodeBase64URLSafeString(payloadString.getBytes()));

    System.out.println(tamperedToken);
    try {
      token = parser.parseToken(tamperedToken, deserializer);
      fail("verification should have failed");
    } catch (SignatureException e) {
      // expected
    }
  }

  private static class SamplePayload extends DefaultPayloadImpl {
    private String foo;
    private int bar;

    public String getFoo() {
      return foo;
    }
    public void setFoo(String foo) {
      this.foo = foo;
    }
    public int getBar() {
      return bar;
    }
    public void setBar(int bar) {
      this.bar = bar;
    }
  }
}
