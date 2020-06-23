package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type stringSlice []string

func (s stringSlice) Contains(value string) bool {
	for _, x := range s {
		if value == x {
			return true
		}
	}
	return false
}

type errInvalidScheme struct {
	Scheme string
}

func (e *errInvalidScheme) Error() string {
	return "invalid scheme " + e.Scheme + ", only http and https are supported"
}

type errInvalidPath struct {
	Path string
}

func (e *errInvalidPath) Error() string {
	return "invalid path " + e.Path
}

type errTLSCheck struct {
	URL        string
	TLSVersion uint16
}

func (e *errTLSCheck) Error() string {
	tlsName := getTLSName(e.TLSVersion)
	return fmt.Sprintf("invalid request to url %s connected using %s", e.URL, tlsName)
}

// version is the published version of the utility
var version string

const (
	// SchemesFlag is the Schemes Flag
	SchemesFlag string = "schemes"
	// HostsFlag is the Hosts Flag
	HostsFlag string = "hosts"
	// PathsFlag is the Paths Flag
	PathsFlag string = "paths"
	// KeyFlag is the Key Flag
	KeyFlag string = "key"
	// KeyFileFlag is the Key File Flag
	KeyFileFlag string = "key-file"
	// CertFlag is the Cert Flag
	CertFlag string = "cert"
	// CertFileFlag is the Cert File Flag
	CertFileFlag string = "cert-file"
	// CAFlag is the CA Flag
	CAFlag string = "ca"
	// CAFileFlag is the CA File Flag
	CAFileFlag string = "ca-file"
	// SkipVerifyFlag is the Skip Verify Flag
	SkipVerifyFlag string = "skip-verify"
	// TriesFlag is the Tries Flag
	TriesFlag string = "tries"
	// BackoffFlag is the Backoff Flag
	BackoffFlag string = "backoff"
	// TimeoutFlag is the Timeout Flag
	TimeoutFlag string = "timeout"
	// ExitOnErrorFlag is the ExitOnError Flag
	ExitOnErrorFlag string = "exit-on-error"
	// LogEnvFlag is the LogEnv Flag
	LogEnvFlag string = "log-env"
	// LogLevelFlag is the LogLevel Flag
	LogLevelFlag string = "log-level"
	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "verbose"
)

func initFlags(flag *pflag.FlagSet) {

	// TLS URLs
	flag.StringP(SchemesFlag, "s", "http,https", "slice of schemes to check")
	flag.String(HostsFlag, "", "comma-separated list of host names to check")
	flag.StringP(PathsFlag, "p", "/tls", "slice of paths to check on each host")

	// Mutual TLS
	flag.String(KeyFlag, "", "path to file of base64-encoded private key for client TLS")
	flag.String(KeyFileFlag, "", "path to file of base64-encoded private key for client TLS")
	flag.String(CertFlag, "", "base64-encoded public key for client TLS")
	flag.String(CertFileFlag, "", "path to file of base64-encoded public key for client TLS")
	flag.String(CAFlag, "", "base64-encoded certificate authority for mutual TLS")
	flag.String(CAFileFlag, "", "path to file of base64-encoded certificate authority for mutual TLS")
	flag.Bool(SkipVerifyFlag, false, "skip certifiate validation")

	// Retry
	flag.Int(TriesFlag, 5, "number of tries")
	flag.Int(BackoffFlag, 1, "backoff in seconds")
	flag.Duration(TimeoutFlag, 5*time.Minute, "timeout duration")

	// Exit
	flag.Bool(ExitOnErrorFlag, false, "exit on first tls check error")

	// Logging
	flag.String(LogEnvFlag, "development", "logging config: development or production")
	flag.String(LogLevelFlag, "error", "log level: debug, info, warn, error, dpanic, panic, or fatal")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level.")

	flag.SortFlags = false
}

func checkConfig(v *viper.Viper) error {
	schemesString := strings.TrimSpace(v.GetString(SchemesFlag))

	if len(schemesString) == 0 {
		return errors.New("missing schemes")
	}

	schemes := stringSlice(strings.Split(schemesString, ","))

	for _, scheme := range schemes {
		if scheme != "http" && scheme != "https" {
			return &errInvalidScheme{Scheme: scheme}
		}
	}

	hosts := v.GetString(HostsFlag)

	if len(hosts) == 0 {
		return errors.New("missing hosts")
	}

	pathsString := v.GetString(PathsFlag)

	if len(pathsString) == 0 {
		return errors.New("missing paths")
	}

	paths := stringSlice(strings.Split(pathsString, ","))

	for _, path := range paths {
		if !strings.HasPrefix(path, "/") {
			return &errInvalidPath{Path: path}
		}
	}

	clientKeyEncoded := v.GetString(KeyFlag)
	clientCertEncoded := v.GetString(CertFlag)
	clientKeyFile := v.GetString(KeyFileFlag)
	clientCertFile := v.GetString(CertFileFlag)

	if len(clientKeyEncoded) > 0 || len(clientCertEncoded) > 0 || len(clientKeyFile) > 0 || len(clientCertFile) > 0 {
		if schemes.Contains("http") {
			return errors.New("cannot use scheme http with client certificate, can only use https")
		}
	}

	return nil
}

func createTLSConfig(clientKey []byte, clientCert []byte, ca []byte, insecureSkipVerify bool, tlsVersion uint16) (*tls.Config, error) {

	keyPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	// #nosec b/c gosec triggers on InsecureSkipVerify
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{keyPair},
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
	}

	if len(ca) > 0 {
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = rootCAs
	}

	return tlsConfig, nil
}

func createHTTPClient(v *viper.Viper, logger *zap.Logger, tlsVersion uint16) (*http.Client, error) {

	verbose := v.GetBool(VerboseFlag)

	clientKeyEncoded := v.GetString(KeyFlag)
	clientCertEncoded := v.GetString(CertFlag)
	skipVerify := v.GetBool(SkipVerifyFlag)
	timeout := v.GetDuration(TimeoutFlag)

	if verbose {
		if skipVerify {
			logger.Info("Skipping client-side certificate validation")
		}
	}

	// Supported TLS versions
	tlsConfig := &tls.Config{
		MinVersion: tlsVersion,
		MaxVersion: tlsVersion,
	}

	if len(clientKeyEncoded) > 0 && len(clientCertEncoded) > 0 {

		clientKey, clientKeyErr := base64.StdEncoding.DecodeString(clientKeyEncoded)
		if clientKeyErr != nil {
			return nil, errors.Wrap(clientKeyErr, "error decoding client key")
		}

		clientCert, clientCertErr := base64.StdEncoding.DecodeString(clientCertEncoded)
		if clientCertErr != nil {
			return nil, errors.Wrap(clientCertErr, "error decoding client cert")
		}

		caBytes := make([]byte, 0)
		if caEncoded := v.GetString(CAFlag); len(caEncoded) > 0 {
			caString, err := base64.StdEncoding.DecodeString(caEncoded)
			if err != nil {
				return nil, errors.Wrap(err, "error decoding certificate authority")
			}
			caBytes = []byte(caString)
		}

		var tlsConfigErr error
		tlsConfig, tlsConfigErr = createTLSConfig([]byte(clientKey), []byte(clientCert), caBytes, false, tlsVersion)
		if tlsConfigErr != nil {
			return nil, errors.Wrap(tlsConfigErr, "error creating TLS config")
		}

	} else {

		clientKeyFile := v.GetString(KeyFlag)
		clientCertFile := v.GetString(KeyFileFlag)

		if len(clientKeyFile) > 0 && len(clientCertFile) > 0 {

			clientKey, clientKeyErr := ioutil.ReadFile(clientKeyFile) // #nosec b/c we need to read a file from a user-defined path
			if clientKeyErr != nil {
				return nil, errors.Wrap(clientKeyErr, "error reading client key file at "+clientKeyFile)
			}

			clientCert, clientCertErr := ioutil.ReadFile(clientCertFile) // #nosec b/c we need to read a file from a user-defined path
			if clientCertErr != nil {
				return nil, errors.Wrap(clientCertErr, "error reading client cert file at "+clientKeyFile)
			}

			caBytes := make([]byte, 0)
			if caFile := v.GetString(CAFlag); len(caFile) > 0 {
				content, err := ioutil.ReadFile(caFile) // #nosec b/c we need to read a file from a user-defined path
				if err != nil {
					return nil, errors.Wrap(err, "error reading ca file at "+caFile)
				}
				caBytes = content
			}
			var tlsConfigErr error
			tlsConfig, tlsConfigErr = createTLSConfig(clientKey, clientCert, caBytes, false, tlsVersion)
			if tlsConfigErr != nil {
				return nil, errors.Wrap(tlsConfigErr, "error creating TLS config")
			}
		}
	}

	httpTransport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
	return httpClient, nil

}

func checkURLWillNotConnect(httpClient *http.Client, url string, logger *zap.Logger) error {
	resp, err := httpClient.Get(url)
	if err == nil {
		return &errTLSCheck{URL: url, TLSVersion: resp.TLS.Version}
	}
	return nil
}

func createLogger(env string, level string) (*zap.Logger, error) {
	loglevel := zapcore.Level(uint8(0))
	err := (&loglevel).UnmarshalText([]byte(level))
	if err != nil {
		return nil, err
	}
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(loglevel)
	var loggerConfig zap.Config
	if env == "production" || env == "prod" {
		loggerConfig = zap.NewProductionConfig()
	} else {
		loggerConfig = zap.NewDevelopmentConfig()
	}
	loggerConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	loggerConfig.Level = atomicLevel
	loggerConfig.DisableStacktrace = true
	return loggerConfig.Build(zap.AddStacktrace(zap.ErrorLevel))
}

func getTLSName(tlsVersion uint16) string {
	var tlsName string
	switch tlsVersion {
	case tls.VersionTLS10:
		tlsName = "TLS v1.0"
	case tls.VersionTLS11:
		tlsName = "TLS v1.1"
	case tls.VersionTLS12:
		tlsName = "TLS v1.2"
	case tls.VersionTLS13:
		tlsName = "TLS v1.3"
	}
	return tlsName
}

func main() {

	root := cobra.Command{
		Use:   "tls-checker [flags]",
		Short: "Website TLS Check",
		Long:  "Website TLS Check",
	}

	completionCommand := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long:  "To install completion scripts run:\ntls-checker completion > /usr/local/etc/bash_completion.d/find-guardduty-user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	}
	root.AddCommand(completionCommand)

	tlsCheckerCheckCommand := &cobra.Command{
		Use:                   "check [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Website TLS Check",
		Long:                  "Website TLS Check",
		RunE:                  tlsCheckerCheckFunction,
	}
	initFlags(tlsCheckerCheckCommand.Flags())
	root.AddCommand(tlsCheckerCheckCommand)

	tlsCheckerVersionCommand := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the version",
		Long:                  "Print the version",
		RunE:                  tlsCheckerVersionFunction,
	}
	root.AddCommand(tlsCheckerVersionCommand)

	if err := root.Execute(); err != nil {
		panic(err)
	}
}

func tlsCheckerVersionFunction(cmd *cobra.Command, args []string) error {
	if len(version) == 0 {
		fmt.Println("development")
		return nil
	}
	fmt.Println(version)
	return nil
}

func tlsCheckerCheckFunction(cmd *cobra.Command, args []string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	err := cmd.ParseFlags(args)
	if err != nil {
		return err
	}

	flag := cmd.Flags()

	v := viper.New()
	bindErr := v.BindPFlags(flag)
	if bindErr != nil {
		return bindErr
	}
	v.SetEnvPrefix("TLSCHECKER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	tlsCheckErrors := make([]error, 0)
	defer func() {
		if len(tlsCheckErrors) > 0 {
			os.Exit(1)
		}
	}()

	logger, err := createLogger(v.GetString(LogEnvFlag), v.GetString(LogLevelFlag))
	if err != nil {
		log.Fatal(err.Error())
	}

	defer func() {
		_ = logger.Sync()
	}()

	err = checkConfig(v)
	if err != nil {
		switch e := err.(type) {
		case *errInvalidPath:
			logger.Fatal(e.Error(), zap.String("path", e.Path))
		case *errInvalidScheme:
			logger.Fatal(e.Error(), zap.String("scheme", e.Scheme))
		}
		logger.Fatal(err.Error())
	}

	verbose := v.GetBool(VerboseFlag)
	schemes := strings.Split(strings.TrimSpace(v.GetString(SchemesFlag)), ",")
	hosts := strings.Split(strings.TrimSpace(v.GetString(HostsFlag)), ",")
	paths := strings.Split(strings.TrimSpace(v.GetString(PathsFlag)), ",")

	// TLS Versions that should not work
	var invalidTLSVersions = []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		// For Testing use these values
		// tls.VersionTLS12,
		// tls.VersionTLS13,
	}

	for _, tlsVersion := range invalidTLSVersions {

		tlsName := getTLSName(tlsVersion)

		httpClient, err := createHTTPClient(v, logger, tlsVersion)
		if err != nil {
			logger.Fatal(errors.Wrap(err, "error creating http client").Error())
		}

		exitOnError := v.GetBool(ExitOnErrorFlag)

		for _, scheme := range schemes {
			for _, host := range hosts {
				for _, path := range paths {
					url := scheme + "://" + host + path
					if verbose {
						logger.Info("checking url will not connect with invalid TLS", zap.String("url", url), zap.String("tlsVersion", tlsName))
					}
					err := checkURLWillNotConnect(httpClient, url, logger)
					if err != nil {
						if exitOnError {
							logger.Fatal(err.Error())
						} else {
							logger.Warn(err.Error())
							tlsCheckErrors = append(tlsCheckErrors, err)
						}
					}
				}
			}
		}
	}
	return nil
}
