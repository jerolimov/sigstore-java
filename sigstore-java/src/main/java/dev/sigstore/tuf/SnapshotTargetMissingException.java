package dev.sigstore.tuf;

public class SnapshotTargetMissingException extends TufException {
  public SnapshotTargetMissingException(String targetName) {
    super(String.format("Snapshot target [%s] was missing from updated snapshot.json", targetName));
  }
}
