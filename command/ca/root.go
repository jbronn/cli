package ca

import (
	"crypto/tls"
	"net/http"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

func rootComand() cli.Command {
	return cli.Command{
		Name:   "root",
		Action: command.ActionFunc(rootAction),
		Usage:  "download and validate the root certificate",
		UsageText: `**step ca root** <root-file>
		[**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>]`,
		Description: `**step ca root** downloads and validates the root certificate from the
certificate authority.

## POSITIONAL ARGUMENTS

<root-file>
:  File to write root certificate (PEM format)

## EXAMPLES

Get the root fingerprint in the CA:
'''
$ step certificate fingerprint /path/to/root_ca.crt
0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Download the root certificate from the configured certificate authority:
'''
$ step ca root root_ca.crt \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Download the root certificate using a given certificate authority:
'''
$ step ca root root_ca.crt \
  --ca-url https://ca.smallstep.com:9000 \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Force,
			fingerprintFlag,
		},
	}
}

func rootAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	caURL := ctx.String("ca-url")
	fingerprint := ctx.String("fingerprint")
	rootFile := ctx.Args().Get(0)

	switch {
	case len(caURL) == 0:
		return errs.RequiredFlag(ctx, "ca-url")
	case len(fingerprint) == 0:
		return errs.RequiredFlag(ctx, "fingerprint")
	}

	tr := getInsecureTransport()
	client, err := ca.NewClient(caURL, ca.WithTransport(tr))
	if err != nil {
		return err
	}

	// Root already validates the certificate
	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	if _, err := pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0600)); err != nil {
		return err
	}

	ui.Printf("The root certificate has been saved in %s.\n", rootFile)
	return nil
}

func getInsecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
