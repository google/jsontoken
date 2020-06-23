package net.oauth.jsontoken.exceptions;

public class InvalidJsonTokenException extends Exception {
  private final ErrorCode errorCode;

  public InvalidJsonTokenException(ErrorCode errorCode) {
    super();
    this.errorCode = errorCode;
  }

  public InvalidJsonTokenException(ErrorCode errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  public InvalidJsonTokenException(ErrorCode errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public InvalidJsonTokenException(ErrorCode errorCode, Throwable cause) {
    super(cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }

}
