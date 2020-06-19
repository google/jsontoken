package net.oauth.jsontoken;

import static org.junit.Assert.assertThrows;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.gson.JsonParseException;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.AsyncVerifierProvider;
import net.oauth.jsontoken.discovery.AsyncVerifierProviders;
import java.security.SignatureException;
import java.util.concurrent.*;

public class AsyncJsonTokenParserTest extends JsonTokenTestBase {

  private AsyncVerifierProviders asyncLocators;
  private AsyncVerifierProviders asyncLocatorsFromRuby;
  private Executor executor;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    AsyncVerifierProvider hmacLocator = (issuer, keyId) -> Futures.immediateFuture(
        locators.getVerifierProvider(SignatureAlgorithm.HS256).findVerifier(issuer, keyId));
    AsyncVerifierProvider rsaLocator = (issuer, keyId) -> Futures.immediateFuture(
        locators.getVerifierProvider(SignatureAlgorithm.RS256).findVerifier(issuer, keyId));

    asyncLocators = new AsyncVerifierProviders();
    asyncLocators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
    asyncLocators.setVerifierProvider(SignatureAlgorithm.RS256, rsaLocator);

    AsyncVerifierProvider hmacLocatorFromRuby = (issuer, keyId) -> Futures.immediateFuture(
        locatorsFromRuby.getVerifierProvider(SignatureAlgorithm.HS256).findVerifier(issuer, keyId));

    asyncLocatorsFromRuby = new AsyncVerifierProviders();
    asyncLocatorsFromRuby.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocatorFromRuby);

    executor = Executors.newFixedThreadPool(4);
  }

  public void testVerify_valid() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    parser.verify(checkToken).get();
  }

  public void testVerify_badSignature() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_BAD_SIG);
    assertCause(
        SignatureException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerify_unsupportedSignature() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    assertCause(
        IllegalArgumentException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerify_noVerifiers() throws Exception {
    AsyncVerifierProvider noLocator = (signerId, keyId) -> Futures.immediateFuture(null);
    AsyncVerifierProviders noLocators = new AsyncVerifierProviders();
    noLocators.setVerifierProvider(SignatureAlgorithm.HS256, noLocator);

    AsyncJsonTokenParser parser = getAsyncJsonTokenParser(noLocators, new IgnoreAudience());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    assertCause(
        IllegalStateException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerifyAndDeserialize_valid() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING).get();
    assertHeader(token);
    assertPayload(token);
  }

  public void testVerifyAndDeserialize_deserializeFail() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    assertCause(
        JsonParseException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_CORRUPT_PAYLOAD).get()
    );
  }

  public void testVerifyAndDeserialize_verifyFail() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    assertCause(
        SignatureException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_BAD_SIG).get()
    );
  }

  public void testVerifyAndDeserialize_tokenFromRuby() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser(asyncLocatorsFromRuby, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY).get();

    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("JWT", token.getHeader().get(JsonToken.TYPE_HEADER).getAsString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
  }

  private AsyncJsonTokenParser getAsyncJsonTokenParser() {
    return new AsyncJsonTokenParser(clock, asyncLocators, executor, new IgnoreAudience());
  }

  private AsyncJsonTokenParser getAsyncJsonTokenParser(AsyncVerifierProviders providers, Checker... checkers) {
    return new AsyncJsonTokenParser(clock, providers, executor, checkers);
  }

  private <T extends Throwable> void assertCause(Class<T> throwableClass, Callable func) throws Exception {
    try {
      func.call();
      fail("Expected ExecutionException with the cause: " + throwableClass.getName());
    } catch (ExecutionException e) {
      assertThrows(
          throwableClass,
          () -> {
            throw e.getCause();
          }
      );
    }
  }

}
