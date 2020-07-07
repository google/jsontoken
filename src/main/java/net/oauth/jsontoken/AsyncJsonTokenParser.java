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
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
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
   * {@link ErrorCode#BAD_HEADER} if the header does not have all of the required parameters,
   * {@link ErrorCode#BAD_SIGNATURE} if the signature is invalid,
   * {@link ErrorCode#BAD_TIME_RANGE} if the IAT is after EXP or the token is in the future,
   * {@link ErrorCode#EXPIRED_TOKEN} if the token is expired,
   * {@link ErrorCode#MALFORMED_TOKEN_STRING} if the tokenString is not a properly formed JWT,
   * {@link ErrorCode#NO_VERIFIER} if there is no valid verifier for the (issuer, keyId) pair,
   * {@link ErrorCode#UNKNOWN} if any of the checkers fail,
   * {@link ErrorCode#UNSUPPORTED_ALGORITHM} if the signature algorithm is unsupported
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will fail if the token fails verification.
   */
  public ListenableFuture<Void> verify(JsonToken jsonToken) {
    ListenableFuture<List<Verifier>> futureVerifiers = provideVerifiers(jsonToken);
    // Use AsyncFunction instead of Function to allow for checked exceptions to propagate forward
    AsyncFunction<List<Verifier>, Void> verifyFunction =
        verifiers -> {
          try {
            verify(jsonToken, verifiers);
          } catch (Exception e) {
            return getFailedFuture(e);
          }
          return Futures.immediateVoidFuture();
        };

    return Futures.transformAsync(futureVerifiers, verifyFunction, executor);
  }

  /**
   * Parses and verifies a JSON Token.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} is an {@link InvalidJsonTokenException}
   * with an error code of:
   * {@link ErrorCode#BAD_HEADER} if the header does not have all of the required parameters,
   * {@link ErrorCode#BAD_SIGNATURE} if the signature is invalid,
   * {@link ErrorCode#BAD_TIME_RANGE} if the IAT or EXP is invalid (IAT after EXP or future token),
   * {@link ErrorCode#EXPIRED_TOKEN} if the token is expired,
   * {@link ErrorCode#MALFORMED_TOKEN_STRING} if tokenString is not a properly formed JWT,
   * {@link ErrorCode#NO_VERIFIER} if there is no valid verifier for the (issuer, keyId) pair,
   * {@link ErrorCode#UNKNOWN} if any of the checkers fail,
   * {@link ErrorCode#UNSUPPORTED_ALGORITHM} if the signature algorithm is unsupported
   *
   * @param tokenString the serialized token that is to parsed and verified.
   * @return a {@link ListenableFuture} that will return the deserialized {@link JsonObject},
   * suitable for passing to the constructor of {@link JsonToken}
   * or equivalent constructor of {@link JsonToken} subclasses.
   */
  public ListenableFuture<JsonToken> verifyAndDeserialize(String tokenString) {
    JsonToken jsonToken;
    try {
      jsonToken = deserialize(tokenString);
    } catch (Exception e) {
      return getFailedFuture(e);
    }

    return Futures.transform(verify(jsonToken), unused -> jsonToken, executor);
  }

  /**
   * Use {@link AsyncVerifierProviders} to get future that will return a list of verifiers
   * for this token.
   * This method is not expected to throw exceptions when returning a future. However,
   * when getting the result of the future, an {@link ExecutionException} may be thrown
   * in which {@link ExecutionException#getCause()} is an {@link InvalidJsonTokenException}
   * with an error code of:
   * {@link ErrorCode#BAD_HEADER} if the header does not have all of the required parameters,
   * {@link ErrorCode#NO_VERIFIER} if there is no valid verifier for the (issuer, keyId) pair,
   * {@link ErrorCode#UNSUPPORTED_ALGORITHM} if the signature algorithm is unsupported
   *
   * @param jsonToken
   * @return a {@link ListenableFuture} that will return a list of verifiers
   */
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
      return getFailedFuture(e);
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
   * Converts exceptions (when applicable) to {@link InvalidJsonTokenException}
   * for better exception handling in the asynchronous parser.
   *
   * @return a failed {@link ListenableFuture}
   */
  private ListenableFuture getFailedFuture(Exception e) {
    Throwable cause = e.getCause();
    if (cause != null && InvalidJsonTokenException.class.isInstance(cause)) {
      InvalidJsonTokenException invalidJsonTokenException = (InvalidJsonTokenException) cause;
      if (invalidJsonTokenException.getErrorCode().equals(ErrorCode.ILLEGAL_STATE)) {
        return Futures.immediateFailedFuture(
            new IllegalStateException(e));
      }
      return Futures.immediateFailedFuture(
          new InvalidJsonTokenException(invalidJsonTokenException.getErrorCode(), e));
    }

    if (JsonParseException.class.isInstance(e)) {
      return Futures.immediateFailedFuture(
          new InvalidJsonTokenException(ErrorCode.MALFORMED_TOKEN_STRING, e));
    }

    if (RuntimeException.class.isInstance(e)) {
      return Futures.immediateFailedFuture(e);
    }

    return Futures.immediateFailedFuture(
        new InvalidJsonTokenException(ErrorCode.UNKNOWN, e));
  }

}
