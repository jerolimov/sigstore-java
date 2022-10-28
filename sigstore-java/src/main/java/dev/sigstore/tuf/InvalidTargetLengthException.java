package dev.sigstore.tuf;

public class InvalidTargetLengthException extends TufException {
  public InvalidTargetLengthException(String targetName, int expectedLength, int actualLength) {
    super(String.format("Target (%s) has a length (%d) which does not match the targets.json metadata (%d)", targetName, actualLength, expectedLength));
  }
}
