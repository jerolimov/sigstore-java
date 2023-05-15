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
package fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import dev.sigstore.KeylessSignature;
import dev.sigstore.KeylessSigner;
import dev.sigstore.fulcio.client.FulcioVerificationException;
import dev.sigstore.fulcio.client.UnsupportedAlgorithmException;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class KeylessSigningFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      KeylessSigner signer = KeylessSigner.builder().sigstorePublicDefaults().build();
      KeylessSignature result = signer.sign(data.consumeRemainingAsBytes());

      result.getDigest();
      result.getCertPath();
      result.getSignature();
      result.getEntry();
    } catch (IOException
        | InvalidAlgorithmParameterException
        | CertificateException
        | InvalidKeySpecException
        | NoSuchAlgorithmException
        | InvalidKeyException
        | InterruptedException
        | SignatureException
        | RekorVerificationException
        | OidcException
        | UnsupportedAlgorithmException
        | FulcioVerificationException
        | RekorParseException e) {
      // known exceptions
    }
  }
}
