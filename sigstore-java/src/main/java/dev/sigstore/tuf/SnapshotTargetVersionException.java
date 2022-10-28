package dev.sigstore.tuf;

public class SnapshotTargetVersionException extends TufException {
  public SnapshotTargetVersionException(String targetName, int invalidVersion, int currentVersion) {
    super(String.format("The updated target [%s] version [%d] is not equal to or greater than the current version [%d].", targetName, invalidVersion, currentVersion));
  }
}
