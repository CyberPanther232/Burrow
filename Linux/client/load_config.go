package main

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

// Linux/client/load_config.go
// Configuration loading functions for Linux client build
// Developer: CyberPanther232

type ClientConfig struct {
	ServerAddress string `yaml:"ServerAddress"`
	ServerPort    int    `yaml:"ServerPort"`
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func loadClientConfig(path string) (*ClientConfig, error) {
	if !fileExists(path) {
		return nil, errors.New("configuration file does not exist")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config = &ClientConfig{}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
