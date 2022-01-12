package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"k8s.io/client-go/util/cert"
)

func ParseKey(data []byte) (*rsa.PublicKey, error) {
	certs, err := cert.ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return nil, errors.New("failed to read any certificates")
	}

	cert, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key but found %v", certs[0].PublicKey)
	}

	return cert, nil
}

func EncryptSecretItem(w io.Writer, secretName, ns string, data []byte, scope ssv1alpha1.SealingScope, pubKey *rsa.PublicKey) error {
	label := ssv1alpha1.EncryptionLabel(ns, secretName, scope)
	out, err := crypto.HybridEncrypt(rand.Reader, pubKey, data, label)
	if err != nil {
		return err
	}
	fmt.Fprint(w, base64.StdEncoding.EncodeToString(out))
	return nil
}
