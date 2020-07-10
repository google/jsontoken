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

import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.AsyncFunction;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.security.SignatureException;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import javax.annotation.Nonnull;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.AsyncVerifierProvider;
import net.oauth.jsontoken.discovery.AsyncVerifierProviders;
import net.oauth.jsontoken.exceptions.ErrorCode;
import net.oauth.jsontoken.exceptions.InvalidJsonTokenException;

/**
 * The asynchronous counterpart of {@link JsonTokenParser}.
 * Class that parses and verifies JSON Tokens asynchronously.
 */
public final class AsyncJsonTokenParser extends AbstractJsonTokenParser {
  private final AsyncVerifierProviders asyncVerifierProviders;
  private final Executor executor;

  /**
   * Creates a new {@link AsyncJsonTokenParser}.
   *
   * @param clock a clock object that will decide whether a given token is currently valid or not.
   * @param asyncVerifierProviders an object that provides signature verifiers asynchronously
   *   based on a signature algorithm, the signer, and key ids.
   * @param executor an executor to run the tasks before and after getting the verifiers
   * @param checkers an array of checkers that validates the parameters in the JSON token.
   */
  public AsyncJsonTokenParser(
      Clock clock,
      AsyncVerifierProviders asyncVerifierProviders,
      Executor executor,
      Checker... checkers) {
    super(clock, checkers);
    this.asyncVerifierProviders = Preconditions.checkNotNull(asyncVerifierProviders);
    this.executor = Preconditions.checkNotNull(executor);
  }

  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims
   * (iat, exp). Uses {@link AsyncVerifierProviders} to obtain the secret key.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} is an {@link InvalidJsonTokenException}
   * with an error code of:
   * <ul>
   *   <li>{@link ErrorCode#BAD_HEADER}:
   *     if the header does not have all of the required parameters</li>
   *   <li>{@link ErrorCode#BAD_SIGNATURE}:
   *     if the signature is invalid</li>
   *   <li>{@link ErrorCode#BAD_TIME_RANGE}:
   *     if the IAT is after EXP or the token is in the future</li>
   *   <li>{@link ErrorCode#EXPIRED_TOKEN}:
   *     if the token is expired</li>
   *   <li>{@link ErrorCode#MALFORMED_TOKEN_STRING}:
   *     if the tokenString is not a properly formatted JWT</li>
   *   <li>{@link ErrorCode#NO_VERIFIER}:
   *     if there is no valid verifier for the (issuer, keyId) pair</li>
   *   <li>{@link ErrorCode#UNKNOWN}:
   *     if any of the checkers fail</li>
   *   <li>{@link ErrorCode#UNSUPPORTED_ALGORITHM}:
   *     if the signature algorithm is unsupported</li>
   * </ul>
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will fail if the token fails verification.
   */
  @Nonnull
  public ListenableFuture<Void> verify(JsonToken jsonToken) {
    ListenableFuture<List<Verifier>> futureVerifiers = provideVerifiers(jsonToken);
    // Use AsyncFunction instead of Function to allow for checked exceptions to propagate forward
    AsyncFunction<List<Verifier>, Void> verifyFunction =
        verifiers -> {
          verify(jsonToken, verifiers);
          return Futures.immediateVoidFuture();
        };

    ListenableFuture<Void> result =
        Futures.transformAsync(futureVerifiers, verifyFunction, executor);
    return mapExceptions(result);
  }

  /**
   * Parses and verifies a JSON Token.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} is an {@link InvalidJsonTokenException}
   * with an error code of:
   * <ul>
   *   <li>{@link ErrorCode#BAD_HEADER}
   *     if the header does not have all of the required parameters</li>
   *   <li>{@link ErrorCode#BAD_SIGNATURE}
   *     if the signature is invalid</li>
   *   <li>{@link ErrorCode#BAD_TIME_RANGE}
   *     if the IAT is after EXP or the token is in the future</li>
   *   <li>{@link ErrorCode#EXPIRED_TOKEN}
   *     if the token is expired</li>
   *   <li>{@link ErrorCode#MALFORMED_TOKEN_STRING}
   *     if the tokenString is not a properly formed JWT</li>
   *   <li>{@link ErrorCode#NO_VERIFIER}
   *     if there is no valid verifier for the (issuer, keyId) pair</li>
   *   <li>{@link ErrorCode#UNKNOWN}
   *     if any of the checkers fail</li>
   *   <li>{@link ErrorCode#UNSUPPORTED_ALGORITHM}
   *     if the signature algorithm is unsupported</li>
   * </ul>
   *
   * @param tokenString the serialized token that is to parsed and verified.
   * @return a {@link ListenableFuture} that will return the deserialized {@link JsonObject},
   * suitable for passing to the constructor of {@link JsonToken}
   * or equivalent constructor of {@link JsonToken} subclasses.
   */
  @Nonnull
  public ListenableFuture<JsonToken> verifyAndDeserialize(String tokenString) {
    JsonToken jsonToken;
    try {
      jsonToken = deserialize(tokenString);
    } catch (InvalidJsonTokenException e) {
      return Futures.immediateFailedFuture(e);
    }

    ListenableFuture<JsonToken> result =
        Futures.transform(verify(jsonToken), unused -> jsonToken, executor);
    return mapExceptions(result);
  }

  /**
   * Decodes the JWT token string into a JsonToken object. Does not perform
   * any validation of headers or claims.
   * Identical to {@link AbstractJsonTokenParser#deserializeInternal(String)},
   * except exceptions are caught and rethrown as {@link InvalidJsonTokenException}.
   *
   * @param tokenString The original encoded representation of a JWT
   * @return Unverified contents of the JWT as a JsonToken
   * @throws InvalidJsonTokenException with {@link ErrorCode#MALFORMED_TOKEN_STRING}
   *   if the tokenString is not a properly formatted JWT.
   */
  public JsonToken deserialize(String tokenString) throws InvalidJsonTokenException {
    return mapExceptions(() -> deserializeInternal(tokenString));
  }

  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims
   * (iat, exp). Does not need VerifierProviders because verifiers are passed in
   * directly.
   * Identical to {@link AbstractJsonTokenParser#verifyInternal(JsonToken, List)},
   * except exceptions are caught and rethrown as {@link InvalidJsonTokenException}.
   *
   * @param jsonToken the token to verify
   * @throws InvalidJsonTokenException with the error code
   * <ul>
   *   <li>{@link ErrorCode#BAD_SIGNATURE}
   *     if the signature is invalid</li>
   *   <li>{@link ErrorCode#BAD_TIME_RANGE}
   *     if the IAT is after EXP or the token is in the future</li>
   *   <li>{@link ErrorCode#MALFORMED_TOKEN_STRING}
   *     if the tokenString is not a properly formed JWT</li>
   *   <li>{@link ErrorCode#UNKNOWN}
   *     if any of the checkers fail</li>
   * </ul>
   */
  public void verify(JsonToken jsonToken, List<Verifier> verifiers)
      throws InvalidJsonTokenException {
    mapExceptions(() -> {
      verifyInternal(jsonToken, verifiers);
      return null;
    });
  }

  /**
   * Verifies that a JSON Web Token's signature is valid.
   * Identical to {@link AbstractJsonTokenParser#signatureIsValidInternal(String, List)},
   * except exceptions are caught and rethrown as {@link InvalidJsonTokenException}.
   *
   * @param tokenString the encoded and signed JSON Web Token to verify.
   * @param verifiers used to verify the signature. These usually encapsulate
   *   secret keys.
   * @throws InvalidJsonTokenException with {@link ErrorCode#MALFORMED_TOKEN_STRING}
   *   if the tokenString is not a properly formatted JWT.
   */
  public boolean signatureIsValid(String tokenString, List<Verifier> verifiers)
      throws InvalidJsonTokenException {
    return mapExceptions(() -> signatureIsValidInternal(tokenString, verifiers));
  }

  /**
   * Use {@link AsyncVerifierProviders} to get future that will return a list of verifiers
   * for this token.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} is an {@link InvalidJsonTokenException}
   * with an error code of:
   * <ul>
   *   <li>{@link ErrorCode#BAD_HEADER}
   *     if the header does not have all of the required parameters</li>
   *   <li>{@link ErrorCode#NO_VERIFIER}
   *     if there is no valid verifier for the (issuer, keyId) pair</li>
   *   <li>{@link ErrorCode#UNSUPPORTED_ALGORITHM}
   *     if the signature algorithm is unsupported</li>
   * </ul>
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will return a list of verifiers
   */
  @Nonnull
  private ListenableFuture<List<Verifier>> provideVerifiers(JsonToken jsonToken) {
    ListenableFuture<List<Verifier>> futureVerifiers;
    try {
      SignatureAlgorithm signatureAlgorithm = jsonToken.getSignatureAlgorithm();
      AsyncVerifierProvider provider =
          asyncVerifierProviders.getVerifierProvider(signatureAlgorithm);
      if (provider == null) {
        return Futures.immediateFailedFuture(
            new InvalidJsonTokenException(
                ErrorCode.UNSUPPORTED_ALGORITHM,
                "Signature algorithm not supported: " + signatureAlgorithm));
      }
      futureVerifiers = provider.findVerifier(jsonToken.getIssuer(), jsonToken.getKeyId());
    } catch (Exception e) {
      return Futures.immediateFailedFuture(e);
    }

    // Use AsyncFunction instead of Function to allow for checked exceptions to propagate forward
    AsyncFunction<List<Verifier>, List<Verifier>> checkNullFunction =
        verifiers -> {
          if (verifiers == null || verifiers.isEmpty()) {
            return Futures.immediateFailedFuture(
                new InvalidJsonTokenException(
                    ErrorCode.NO_VERIFIER,
                    "No valid verifier for issuer: " + jsonToken.getIssuer()));
          }
          return Futures.immediateFuture(verifiers);
        };

    return Futures.transformAsync(futureVerifiers, checkNullFunction, executor);
  }

  /**
   * Remaps exceptions, when applicable, to {@link InvalidJsonTokenException} for improved
   * exception handling in the asynchronous parser. Otherwise, the original exception is returned.
   */
  private Exception mapException(Exception originalException) {
    Throwable cause = originalException.getCause();
    if (cause instanceof InvalidJsonTokenException) {
      InvalidJsonTokenException invalidJsonTokenException = (InvalidJsonTokenException) cause;
      if (invalidJsonTokenException.getErrorCode().equals(ErrorCode.ILLEGAL_STATE)) {
        return new IllegalStateException(originalException);
      }

      return new InvalidJsonTokenException(
          invalidJsonTokenException.getErrorCode(), originalException);
    }

    if (originalException instanceof SignatureException) {
      return new InvalidJsonTokenException(ErrorCode.UNKNOWN, originalException);
    }

    if (originalException instanceof JsonParseException) {
      return new InvalidJsonTokenException(ErrorCode.MALFORMED_TOKEN_STRING, originalException);
    }

    return originalException;
  }

  /**
   * Rethrows any {@link SignatureException}, any {@link RuntimeException}s, or any
   * {@link Exception} where {@link Exception#getCause()} is {@link InvalidJsonTokenException}.
   */
  private <T> T mapExceptions(Callable<T> callable) throws InvalidJsonTokenException {
    try {
      return callable.call();
    } catch (Exception e) {
      Exception rethrownException = mapException(e);
      if (rethrownException instanceof InvalidJsonTokenException) {
        throw (InvalidJsonTokenException) rethrownException;
      }
      if (rethrownException instanceof RuntimeException) {
        throw (RuntimeException) rethrownException;
      }

      throw new IllegalStateException("Unexpected checked exception.", rethrownException);
    }
  }

  /**
   * Catches any failed futures and returns a new future with a mapped exception.
   * Unlike {@link #mapExceptions(Callable)}, this function supports all exceptions.
   */
  private <T> ListenableFuture<T> mapExceptions(ListenableFuture<T> result) {
    return Futures.catchingAsync(result, Exception.class,
        exception -> {
          throw mapException(exception);
        }, executor);
  }

}
