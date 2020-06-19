/**
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
 *
 */
package net.oauth.jsontoken;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.AsyncFunction;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.gson.JsonObject;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.AsyncVerifierProviders;
import java.security.SignatureException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

/**
 * The asynchronous counterpart of {@link JsonTokenParser}.
 * Class that parses and verifies JSON Tokens asynchronously.
 */
public class AsyncJsonTokenParser extends AbstractJsonTokenParser {
  private final AsyncVerifierProviders asyncVerifierProviders;
  private final Executor executor;

  /**
   * Creates a new {@link AbstractJsonTokenParser} with a default system clock. The default
   * system clock tolerates a clock skew of up to {@link SystemClock#DEFAULT_ACCEPTABLE_CLOCK_SKEW}.
   *
   * @param asyncVerifierProviders an object that provides signature verifiers asynchronously
   *   based on a signature algorithm, the signer, and key ids.
   * @param executor an executor to run the tasks before and after getting the verifiers
   * @param checker an audience checker that validates the audience in the JSON token.
   */
  public AsyncJsonTokenParser(
      AsyncVerifierProviders asyncVerifierProviders, Executor executor, Checker checker) {
    this(new SystemClock(), asyncVerifierProviders, executor, checker);
  }

  /**
   * Creates a new {@link JsonTokenParser}.
   *
   * @param clock a clock object that will decide whether a given token is
   *   currently valid or not.
   * @param asyncVerifierProviders an object that provides signature verifiers asynchronously
   *   based on a signature algorithm, the signer, and key ids.
   * @param executor an executor to run the tasks before and after getting the verifiers
   * @param checkers an array of checkers that validates the parameters in the JSON token.
   */
  public AsyncJsonTokenParser(
      Clock clock, AsyncVerifierProviders asyncVerifierProviders, Executor executor, Checker... checkers) {
    super(clock, checkers);
    this.asyncVerifierProviders = Preconditions.checkNotNull(asyncVerifierProviders);
    this.executor = Preconditions.checkNotNull(executor);
  }

  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims
   * (iat, exp). Uses {@link AsyncVerifierProviders} to obtain the secret key.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} follows the same possible exceptions
   * as thrown by {@link JsonTokenParser#verify(JsonToken)}.
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will return a Void
   */
  public ListenableFuture<Void> verify(JsonToken jsonToken) {
    ListenableFuture<List<Verifier>> futureVerifiers = provideVerifiers(jsonToken);
    // Use AsyncFunction instead of Function to allow for checked exceptions to propagate forward
    AsyncFunction<List<Verifier>, Void> verifyFunction =
        verifiers -> Futures.immediateFuture(verifyAndReturnVoid(jsonToken, verifiers));

    return Futures.transformAsync(futureVerifiers, verifyFunction, executor);
  }

  /**
   * Parses, and verifies, a JSON Token.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} follows the same possible exceptions
   * thrown by {@link JsonTokenParser#verifyAndDeserialize(String)}.
   *
   * @param tokenString the serialized token that is to parsed and verified.
   * @return a {@link ListenableFuture} that will return the deserialized {@link JsonObject},
   * suitable for passing to the constructor of {@link JsonToken}
   * or equivalent constructor of {@link JsonToken} subclasses.
   */
  public ListenableFuture<JsonToken> verifyAndDeserialize(String tokenString) {
    ListenableFuture<String> futureTokenString = Futures.immediateFuture(tokenString);
    AsyncFunction<String, JsonToken> verifyFunction =
        tokenStringInput -> {
          JsonToken jsonToken = deserialize(tokenStringInput);
          Function<Void, JsonToken> returnFunction = unused -> jsonToken;
          return Futures.transform(verify(jsonToken), returnFunction, executor);
        };

    return Futures.transformAsync(futureTokenString, verifyFunction, executor);
  }

  /**
   * Use {@link AsyncVerifierProviders} to get future that will return a list of verifiers
   * for this token
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will return a list of verifiers
   */
  private ListenableFuture<List<Verifier>> provideVerifiers(JsonToken jsonToken) {
    ListenableFuture<JsonToken> futureJsonToken = Futures.immediateFuture(jsonToken);
    AsyncFunction<JsonToken, List<Verifier>> findVerifiersFunction =
        token -> asyncVerifierProviders
            .getVerifierProvider(token.getSignatureAlgorithm())
            .findVerifier(token.getIssuer(), token.getKeyId());

    Function<List<Verifier>, List<Verifier>> checkNullFunction =
        verifiers -> {
          if (verifiers == null) {
            throw new IllegalStateException("No valid verifier for issuer: " + jsonToken.getIssuer());
          }
          return verifiers;
        };

    ListenableFuture<List<Verifier>> futureVerifiers =
        Futures.transformAsync(futureJsonToken, findVerifiersFunction, executor);

    return Futures.transform(futureVerifiers, checkNullFunction, executor);
  }

  private Void verifyAndReturnVoid(JsonToken jsonToken, List<Verifier> verifiers) throws SignatureException {
    verify(jsonToken, verifiers);
    return null;
  }

}
