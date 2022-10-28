package dev.sigstore.tuf;

public class SnapshotVersionMismatchException extends TufException {
  public SnapshotVersionMismatchException(int expectedVersion, int actualVersion) {
    super(String.format("Snapshot version (%d) did not match Timestamp resource (%d)", actualVersion, expectedVersion));
  }
}
