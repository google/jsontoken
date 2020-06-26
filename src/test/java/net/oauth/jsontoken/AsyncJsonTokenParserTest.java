package net.oauth.jsontoken;

import static org.junit.Assert.assertThrows;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.gson.JsonParseException;
import java.security.SignatureException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.AsyncVerifierProvider;
import net.oauth.jsontoken.discovery.AsyncVerifierProviders;
import org.junit.function.ThrowingRunnable;

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

    asyncLocators = alg -> {
      if (alg.equals(SignatureAlgorithm.HS256)) {
        return hmacLocator;
      } else if (alg.equals(SignatureAlgorithm.RS256)) {
        return rsaLocator;
      }
      return null;
    };

    AsyncVerifierProvider hmacLocatorFromRuby = (issuer, keyId) -> Futures.immediateFuture(
        locatorsFromRuby.getVerifierProvider(SignatureAlgorithm.HS256).findVerifier(issuer, keyId));

    asyncLocatorsFromRuby = alg -> {
      if (alg.equals(SignatureAlgorithm.HS256)) {
        return hmacLocatorFromRuby;
      }
      return null;
    };

    executor = MoreExecutors.directExecutor();
  }

  public void testVerify_valid() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    parser.verify(checkToken).get();
  }

  public void testVerify_badSignature() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_BAD_SIG);
    assertFailsWithCause(
        SignatureException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerify_unsupportedSignature() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    assertFailsWithCause(
        IllegalArgumentException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerify_noVerifiers() throws Exception {
    AsyncVerifierProvider noLocator = (signerId, keyId) -> Futures.immediateFuture(null);
    AsyncVerifierProviders noLocators = alg -> {
      if (alg.equals(SignatureAlgorithm.HS256)) {
        return noLocator;
      }
      return null;
    };
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser(noLocators, new IgnoreAudience());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);

    assertFailsWithCause(
        IllegalStateException.class,
        () -> parser.verify(checkToken).get()
    );
  }

  public void testVerify_noProviders() throws Exception {
    AsyncVerifierProviders noProviders = alg -> null;
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser(noProviders, new IgnoreAudience());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);

    assertFailsWithCause(
        IllegalArgumentException.class,
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
    assertFailsWithCause(
        JsonParseException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_CORRUPT_PAYLOAD).get()
    );
  }

  public void testVerifyAndDeserialize_verifyFail() throws Exception {
    AsyncJsonTokenParser parser = getAsyncJsonTokenParser();
    assertFailsWithCause(
        SignatureException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_BAD_SIG).get()
    );
  }

  public void testVerifyAndDeserialize_tokenFromRuby() throws Exception {
    AsyncJsonTokenParser parser =
        getAsyncJsonTokenParser(asyncLocatorsFromRuby, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY).get();

    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("JWT", token.getHeader().get(JsonToken.TYPE_HEADER).getAsString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
  }

  private AsyncJsonTokenParser getAsyncJsonTokenParser() {
    return new AsyncJsonTokenParser(clock, asyncLocators, executor, new IgnoreAudience());
  }

  private AsyncJsonTokenParser getAsyncJsonTokenParser(
      AsyncVerifierProviders providers, Checker... checkers) {
    return new AsyncJsonTokenParser(clock, providers, executor, checkers);
  }

  private <T extends Throwable> void assertFailsWithCause(
      Class<T> throwableClass, ThrowingRunnable runnable) {
    ExecutionException e = assertThrows(ExecutionException.class, runnable);
    assertTrue(throwableClass.isInstance(e.getCause()));
  }

}
