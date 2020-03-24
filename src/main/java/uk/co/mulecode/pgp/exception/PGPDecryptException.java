package uk.co.mulecode.pgp.exception;

public class PGPDecryptException extends RuntimeException {

  public PGPDecryptException(String message) {
    super(message);
  }

  public PGPDecryptException(String message, Throwable cause) {
    super(message, cause);
  }
}
