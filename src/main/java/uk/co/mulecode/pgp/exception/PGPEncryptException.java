package uk.co.mulecode.pgp.exception;

public class PGPEncryptException extends RuntimeException {

  public PGPEncryptException(String message) {
    super(message);
  }

  public PGPEncryptException(String message, Throwable cause) {
    super(message, cause);
  }
}
