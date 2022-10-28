package dev.sigstore.tuf;

/**
 * Thrown when a hash check fails for a given resource.
 */
public class InvalidHashException extends TufException {

  public InvalidHashException(String resourceName, String algorithm, String expectedHash, String computedHash) {
    super(String.format("The computed hash(%s) for %s did not match expectations. expected hash: %s, computed hash: %s", algorithm, resourceName, expectedHash, computedHash
    ));
  }
}
