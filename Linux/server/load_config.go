package main

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// Windows/server/load_config.go
// Configuration loading functions for Windows server build
// Developer: CyberPanther232

type ServerConfig struct {
	Address        string `yaml:"Address"`
	Port           int    `yaml:"Port"`
	PrivateKeyFile string `yaml:"PrivateKeyFile"`
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func loadServerConfig(path string) (*ServerConfig, error) {
	if !fileExists(path) {
		return nil, errors.New("configuration file does not exist")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config = &ServerConfig{}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func saveKey(key noise.DHKey) error {
	return os.WriteFile("server.key", key.Private, 0600)
}

func loadKey() (noise.DHKey, error) {
	priv, err := os.ReadFile("server.key")
	if err != nil {
		return noise.DHKey{}, err
	}
	if len(priv) != 32 {
		return noise.DHKey{}, errors.New("invalid private key length")
	}

	var pub, privKey [32]byte
	copy(privKey[:], priv)
	curve25519.ScalarBaseMult(&pub, &privKey)

	return noise.DHKey{
		Private: priv,
		Public:  pub[:],
	}, nil
}
