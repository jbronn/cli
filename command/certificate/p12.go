package certificate

import (
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"

	"software.sslmate.com/src/go-pkcs12"
)

func p12Command() cli.Command {
	return cli.Command{
		Name:   "p12",
		Action: command.ActionFunc(p12Action),
		Usage:  `package a certificate and keys into a .p12 file`,
		UsageText: `step certificate p12 <p12-path> [<crt-path>] [<key-path>]
[**--ca**=<file>] [**--password-file**=<file>]`,
		Description: `**step certificate p12** creates a .p12 (PFX / PKCS12)
file containing certificates and keys. This can then be used to import
into Windows / Firefox / Java applications.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Package a certificate and private key together:

'''
$ step certificate p12 foo.p12 foo.crt foo.key
'''

Package a certificate and private key together, and include an intermediate certificate:

'''
$ step certificate p12 foo.p12 foo.crt foo.key --ca intermediate.crt
'''

Package a CA certificate into a "trust store" for Java applications:

'''
$ step certificate p12 trust.p12 --ca ca.crt
'''`,
		Flags: []cli.Flag{
			cli.StringSliceFlag{
				Name: "ca",
				Usage: `The path to the <file> containing a CA or intermediate certificate to
add to the .p12 file. Use the '--ca' flag multiple times to add
multiple CAs or intermediates.`,
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to encrypt the .p12 file.`,
			},
			flags.Force,
		},
	}
}

func p12Action(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 3); err != nil {
		return err
	}

	p12File := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	caFiles := ctx.StringSlice("ca")
	hasKeyAndCert := crtFile != "" && keyFile != ""

	//If either key or cert are provided, both must be provided
	if !hasKeyAndCert && (crtFile != "" || keyFile != "") {
		return errs.MissingArguments(ctx, "key_file")
	}

	//If no key and cert are provided, ca files must be provided
	if !hasKeyAndCert && len(caFiles) == 0 {
		return errors.Errorf("flag '--%s' must be provided when no <crt_path> and <key_path> are present", "ca")
	}

	x509CAs := []*x509.Certificate{}
	for _, caFile := range caFiles {
		x509Bundle, err := pemutil.ReadCertificateBundle(caFile)
		if err != nil {
			return errors.Wrap(err, "error reading CA certificate")
		}
		x509CAs = append(x509CAs, x509Bundle...)
	}

	var password string
	var err error

	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	if password == "" {
		pass, err := ui.PromptPassword("Please enter a password to encrypt the .p12 file")
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		password = string(pass)
	}

	var pkcs12Data []byte

	if hasKeyAndCert {
		//If we have a key and certificate, we're making an identity store
		x509CertBundle, err := pemutil.ReadCertificateBundle(crtFile)
		if err != nil {
			return errors.Wrap(err, "error reading certificate")
		}

		key, err := pemutil.Read(keyFile)
		if err != nil {
			return errors.Wrap(err, "error reading key")
		}

		//The first certificate in the bundle will be our server cert
		x509Cert := x509CertBundle[0]
		//Any remaning certs will be intermediates for the server
		x509CAs = append(x509CAs, x509CertBundle[1:]...)

		pkcs12Data, err = pkcs12.Encode(rand.Reader, key, x509Cert, x509CAs, password)
		if err != nil {
			return errs.Wrap(err, "failed to encode PKCS12 data")
		}
	} else {
		//If we have only --ca flags, we're making a trust store
		pkcs12Data, err = pkcs12.EncodeTrustStore(rand.Reader, x509CAs, password)
		if err != nil {
			return errs.Wrap(err, "failed to encode PKCS12 data")
		}
	}

	if err := utils.WriteFile(p12File, pkcs12Data, 0600); err != nil {
		return err
	}

	ui.Printf("Your .p12 bundle has been saved as %s.\n", p12File)
	return nil
}
