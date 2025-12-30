// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

// nolint
type AttestBlobCommand struct {
	options.KeyOpts
	CertPath      string
	CertChainPath string

	ArtifactHash string

	StatementPath string
	PredicatePath string
	PredicateType string

	TlogUpload bool
	Timeout    time.Duration

	OutputSignature   string
	OutputAttestation string
	OutputCertificate string

	RekorEntryType string
}

// nolint
func (c *AttestBlobCommand) Exec(ctx context.Context, artifactPath string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if options.NOf(c.PredicatePath, c.StatementPath) != 1 {
		return fmt.Errorf("one of --predicate or --statement must be set")
	}

	if c.RekorEntryType != "dsse" && c.RekorEntryType != "intoto" {
		return fmt.Errorf("unknown value for rekor-entry-type")
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	base := path.Base(artifactPath)

	var payload []byte
	var err error

	if c.StatementPath != "" {
		fmt.Fprintln(os.Stderr, "Using statement from:", c.StatementPath)
		payload, err = os.ReadFile(filepath.Clean(c.StatementPath))
		if err != nil {
			return fmt.Errorf("could not read statement: %w", err)
		}
		if _, err := validateStatement(payload); err != nil {
			return fmt.Errorf("invalid statement: %w", err)
		}

	} else {
		var artifact []byte
		var hexDigest string
		if c.ArtifactHash == "" {
			if artifactPath == "-" {
				artifact, err = io.ReadAll(os.Stdin)
			} else {
				fmt.Fprintln(os.Stderr, "Using payload from:", artifactPath)
				artifact, err = os.ReadFile(filepath.Clean(artifactPath))
			}
			if err != nil {
				return err
			}
		}

		if c.ArtifactHash == "" {
			digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
			if err != nil {
				return err
			}
			hexDigest = strings.ToLower(hex.EncodeToString(digest))
		} else {
			hexDigest = c.ArtifactHash
		}
		predicate, err := predicateReader(c.PredicatePath)
		if err != nil {
			return fmt.Errorf("getting predicate reader: %w", err)
		}
		defer predicate.Close()
		sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
			Predicate: predicate,
			Type:      c.PredicateType,
			Digest:    hexDigest,
			Repo:      base,
		})
		if err != nil {
			return err
		}
		payload, err = json.Marshal(sh)
		if err != nil {
			return err
		}
	}

	bundleOpts := signcommon.CommonBundleOpts{
		Payload:    payload,
		BundlePath: c.BundlePath,
	}

	bundleBytes, err := signcommon.NewBundleWithSigningConfig(ctx, c.KeyOpts, c.CertPath, c.CertChainPath, bundleOpts, c.SigningConfig, c.TrustedMaterial)
	if err != nil {
		return fmt.Errorf("creating bundle: %w", err)
	}

	// if c.BundlePath != "" { // PREVIOUS PR MANDATES THIS
		var contents []byte
		if c.NewBundleFormat {
			contents = bundleBytes
		} else {
			contents, err = signcommon.NewLegacyBundleFromProtoBundle(ctx, bundleBytes)
			if err != nil {
				return fmt.Errorf("creating legacy bundle: %w", err)
			}
		}

		if err := os.WriteFile(c.BundlePath, contents, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Bundle wrote in the file ", c.BundlePath)
	// }

	// Extract components for supplemental/detached outputs
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return fmt.Errorf("unmarshalling bundle: %w", err)
	}

	sig := bundle.GetDsseEnvelope().GetSignatures()
	if len(sig) == 0 {
		return fmt.Errorf("no signatures in bundle")
	}

	envelopeBytes, err := protojson.Marshal(bundle.GetDsseEnvelope())
	if err != nil {
		return fmt.Errorf("marshalling DSSE envelope: %w", err)
	}
	// Get cert from verification material
	var certPEM []byte
	if c := bundle.VerificationMaterial.GetCertificate(); c != nil {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.GetRawBytes(),
		}
		certPEM = pem.EncodeToMemory(pemBlock)
	}

	if c.OutputSignature != "" {
		if err := os.WriteFile(c.OutputSignature, envelopeBytes, 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Signature written in %s\n", c.OutputSignature)
	} else {
		fmt.Fprintln(os.Stdout, string(envelopeBytes))
	}

	if c.OutputAttestation != "" {
		if err := os.WriteFile(c.OutputAttestation, payload, 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Attestation written in %s\n", c.OutputAttestation)
	}

	if c.OutputCertificate != "" {
		if certPEM == nil {
			fmt.Fprintln(os.Stderr, "Could not output signer certificate. Was a certificate used?")
			return nil
		}
		if err := os.WriteFile(c.OutputCertificate, certPEM, 0600); err != nil {
			return fmt.Errorf("create certificate file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Certificate written to file ", c.OutputCertificate)
	}

	return nil
}

func validateStatement(payload []byte) (string, error) {
	var statement *intotov1.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return "", fmt.Errorf("invalid statement: %w", err)
	}
	return statement.PredicateType, nil
}
