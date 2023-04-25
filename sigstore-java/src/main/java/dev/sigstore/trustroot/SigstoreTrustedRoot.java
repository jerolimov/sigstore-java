/*
 * Copyright 2023 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.sigstore.trustroot;

import com.google.common.annotations.VisibleForTesting;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.immutables.value.Value.Immutable;

@Immutable
public abstract class SigstoreTrustedRoot {

  /** A list of certificate authorities associated with this trustroot. */
  public abstract List<CertificateAuthority> getCertificateAuthorities();

  /** A list of binary transparency logs associated with this trustroot. */
  public abstract List<TransparencyLog> getTLogs();

  /** A list of certificate transparency logs associated with this trustroot. */
  public abstract List<TransparencyLog> getCTLogs();

  /** Create an instance from a parsed proto definition of a trustroot. */
  public static SigstoreTrustedRoot from(TrustedRoot proto) throws CertificateException {
    List<CertificateAuthority> certificateAuthorities =
        new ArrayList<>(proto.getCertificateAuthoritiesCount());
    for (var certAuthority : proto.getCertificateAuthoritiesList()) {
      certificateAuthorities.add(CertificateAuthority.from(certAuthority));
    }
    var tlogs =
        proto.getTlogsList().stream().map(TransparencyLog::from).collect(Collectors.toList());
    var ctlogs =
        proto.getCtlogsList().stream().map(TransparencyLog::from).collect(Collectors.toList());

    return ImmutableSigstoreTrustedRoot.builder()
        .certificateAuthorities(certificateAuthorities)
        .tLogs(tlogs)
        .cTLogs(ctlogs)
        .build();
  }

  /**
   * Find transparency log matching the logId and validity time.
   *
   * @param logId a log id
   * @param time a point in time during the logs validity period
   * @return the first log found matching logId and time, or empty if none match
   */
  public Optional<TransparencyLog> getTLog(byte[] logId, Instant time) {
    return getTLog(getTLogs(), logId, time);
  }

  /**
   * Find certificate transparency log matching the logId and validity time.
   *
   * @param logId a log id
   * @param time a point in time during the logs validity period
   * @return the first log found matching logId and time, or empty if none match
   */
  public Optional<TransparencyLog> getCTLog(byte[] logId, Instant time) {
    return getTLog(getCTLogs(), logId, time);
  }

  private Optional<TransparencyLog> getTLog(
      List<TransparencyLog> tlogs, byte[] logId, Instant time) {
    return tlogs.stream()
        .filter(tl -> Arrays.equals(tl.getLogId().getKeyId(), logId))
        .filter(tl -> tl.getPublicKey().getValidFor().getStart().compareTo(time) <= 0)
        .filter(
            tl ->
                tl.getPublicKey().getValidFor().getEnd().orElse(Instant.now()).compareTo(time) >= 0)
        .findAny();
  }

  /**
   * Get the one an only current TLog
   *
   * @return the current active TLog
   * @throws IllegalStateException if trust root does not contain exactly one transparency log
   */
  public TransparencyLog getCurrentTLog() {
    return getCurrentTLog(getTLogs());
  }

  /**
   * Get the one an only current CTLog
   *
   * @return the current active CTLog
   * @throws IllegalStateException if trust root does not contain exactly one active CT log
   */
  public TransparencyLog getCurrentCTLog() {
    return getCurrentTLog(getCTLogs());
  }

  @VisibleForTesting
  static TransparencyLog getCurrentTLog(List<TransparencyLog> tlogs) {
    var current =
        tlogs.stream()
            .filter(tl -> tl.getPublicKey().getValidFor().getEnd().isEmpty())
            .collect(Collectors.toList());
    if (current.size() == 0) {
      throw new IllegalStateException("Trust root contains no current transparency logs");
    }
    if (current.size() > 1) {
      throw new IllegalStateException(
          "Trust root contains multiple current transparency logs (" + current.size() + ")");
    }
    return current.get(0);
  }

  /**
   * Find a CA by validity time, users of this method will need to then compare the key in the leaf
   * to find the exact CA to validate against
   *
   * @param time the time the CA was expected to be valid (usually tlog entry time)
   * @return a list of CAs that were valid at {@code time}
   */
  public List<CertificateAuthority> getCAs(Instant time) {
    return getCertificateAuthorities().stream()
        .filter(ca -> ca.getValidFor().getStart().compareTo(time) <= 0)
        .filter(ca -> ca.getValidFor().getEnd().orElse(Instant.now()).compareTo(time) >= 0)
        .collect(Collectors.toList());
  }

  /**
   * Get the one an only current Certificate Authority
   *
   * @return the current active CA
   * @throws IllegalStateException if trust root does not contain exactly one active CA
   */
  public CertificateAuthority getCurrentCA() {
    return getCurrentCA(getCertificateAuthorities());
  }

  @VisibleForTesting
  static CertificateAuthority getCurrentCA(List<CertificateAuthority> certificateAuthorities) {
    var current =
        certificateAuthorities.stream()
            .filter(ca -> ca.getValidFor().getEnd().isEmpty())
            .collect(Collectors.toList());
    if (current.size() == 0) {
      throw new IllegalStateException("Trust root contains no current certificate authorities");
    }
    if (current.size() > 1) {
      throw new IllegalStateException(
          "Trust root contains multiple current certificate authorities (" + current.size() + ")");
    }
    return current.get(0);
  }
}
