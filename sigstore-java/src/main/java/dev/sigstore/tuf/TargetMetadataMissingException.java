package dev.sigstore.tuf;

public class TargetMetadataMissingException extends TufException {
  public TargetMetadataMissingException(String targetName) {
    super(String.format("The target (%s) has no metadata", targetName));
  }
}
