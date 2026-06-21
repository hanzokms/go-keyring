// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/mtibben/percent"
)

type encryptedFileKeychain struct{}

var tildePrefix = string([]rune{'~', filepath.Separator})

const encryptedFileStoreDir = "~/infisical-keyring"

const shellPassPhraseEnvName = "KMS_VAULT_FILE_PASSPHRASE"

// Get password from macos keyring given service and user name.
func (k encryptedFileKeychain) Get(service, key string) (string, error) {
	filename, err := filename(key)
	if err != nil {
		return "", err
	}

	bytes, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}

	password, err := getEncryptedFilePassphrase()
	if err != nil {
		return "", err
	}

	payload, _, err := jose.Decode(string(bytes), password)
	if err != nil {
		return "", err
	}

	var decoded string
	err = json.Unmarshal([]byte(payload), &decoded)

	return decoded, err
}

// Set stores a secret in the macos keyring given a service name and a user.
func (k encryptedFileKeychain) Set(service, key, password string) error {
	bytes, err := json.Marshal(password)
	if err != nil {
		return err
	}

	if password, err = getEncryptedFilePassphrase(); err != nil {
		return err
	}

	token, err := jose.Encrypt(string(bytes), jose.PBES2_HS256_A128KW, jose.A256GCM, password,
		jose.Headers(map[string]interface{}{
			"created": time.Now().String(),
		}))
	if err != nil {
		return err
	}

	filename, err := filename(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(token), 0600)
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (k encryptedFileKeychain) Delete(service, key string) error {
	filename, err := filename(key)
	if err != nil {
		return err
	}

	return os.Remove(filename)
}

// ExpandTilde will expand tilde (~/ or ~\ depending on OS) for the user home directory.
func ExpandTilde(dir string) (string, error) {
	if strings.HasPrefix(dir, tildePrefix) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = strings.Replace(dir, "~", homeDir, 1)
		// debugf("Expanded file dir to %s", dir)
	}
	return dir, nil
}

var filenameEscape = func(s string) string {
	return percent.Encode(s, "/")
}

func resolveDir() (string, error) {
	if encryptedFileStoreDir == "" {
		return "", errors.New("file keyring: Directory not set for file keyring")
	}

	dir, err := ExpandTilde(encryptedFileStoreDir)
	if err != nil {
		return "", err
	}

	stat, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
	} else if err != nil && stat != nil && !stat.IsDir() {
		err = fmt.Errorf("file keyring: %s is a file, not a directory", dir)
	}

	return dir, err
}

func filename(key string) (string, error) {
	dir, err := resolveDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, filenameEscape(key)), nil
}

func Remove(key string) error {
	filename, err := filename(key)
	if err != nil {
		return err
	}

	return os.Remove(filename)
}

func getEncryptedFilePassphrase() (password string, errorOut error) {
	dir, err := resolveDir()
	if err != nil {
		return "", err
	}

	password = os.Getenv(shellPassPhraseEnvName)
	if password == "" {
		pwd, err := TerminalPrompt(fmt.Sprintf("Enter passphrase to unlock %q", dir))
		if err != nil {
			return "", err
		}
		return pwd, nil
	}

	return password, nil
}
