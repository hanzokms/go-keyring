package keyring

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

const (
	service               = "test-service"
	user                  = "test-user"
	password              = "test-password"
	fileKeyringPassphrase = "some-pass-phrase"
)

// TestSet tests setting a user and password in the keyring.
func TestSet(t *testing.T) {
	err := Set(VAULT_SELECTION_AUTO, service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

func TestSetTooLong(t *testing.T) {
	extraLongPassword := "ba" + strings.Repeat("na", 5000)
	err := Set(VAULT_SELECTION_AUTO, service, user, extraLongPassword)

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// should fail on those platforms
		if err != ErrSetDataTooBig {
			t.Errorf("Should have failed, got: %s", err)
		}
	}
}

// TestGetMultiline tests getting a multi-line password from the keyring
func TestGetMultiLine(t *testing.T) {
	multilinePassword := `this password
has multiple
lines and will be
encoded by some keyring implementiations
like osx`
	err := Set(VAULT_SELECTION_AUTO, service, user, multilinePassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(VAULT_SELECTION_AUTO, service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if multilinePassword != pw {
		t.Errorf("Expected password %s, got %s", multilinePassword, pw)
	}
}

// TestGetMultiline tests getting a multi-line password from the keyring
func TestGetUmlaut(t *testing.T) {
	umlautPassword := "at least on OSX üöäÜÖÄß will be encoded"
	err := Set(VAULT_SELECTION_AUTO, service, user, umlautPassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(VAULT_SELECTION_AUTO, service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if umlautPassword != pw {
		t.Errorf("Expected password %s, got %s", umlautPassword, pw)
	}
}

// TestGetSingleLineHex tests getting a single line hex string password from the keyring.
func TestGetSingleLineHex(t *testing.T) {
	hexPassword := "abcdef123abcdef123"
	err := Set(VAULT_SELECTION_AUTO, service, user, hexPassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(VAULT_SELECTION_AUTO, service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if hexPassword != pw {
		t.Errorf("Expected password %s, got %s", hexPassword, pw)
	}
}

// TestGet tests getting a password from the keyring.
func TestGet(t *testing.T) {
	err := Set(VAULT_SELECTION_AUTO, service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(VAULT_SELECTION_AUTO, service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if password != pw {
		t.Errorf("Expected password %s, got %s", password, pw)
	}
}

// TestGetNonExisting tests getting a secret not in the keyring.
func TestGetNonExisting(t *testing.T) {
	_, err := Get(VAULT_SELECTION_AUTO, service, user+"fake")
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}
}

// TestDelete tests deleting a secret from the keyring.
func TestDelete(t *testing.T) {
	err := Delete(VAULT_SELECTION_AUTO, service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

// TestDeleteNonExisting tests deleting a secret not in the keyring.
func TestDeleteNonExisting(t *testing.T) {
	err := Delete(VAULT_SELECTION_AUTO, service, user+"fake")
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}
}

// TestSet tests setting a user and password in the [file] keyring.
func TestSetForFileKeyring(t *testing.T) {
	// set pass phrase via shell
	os.Setenv(shellPassPhraseEnvName, fileKeyringPassphrase)

	err := Set("file", service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

func TestGetForFileKeyring(t *testing.T) {
	// set pass phrase via shell
	os.Setenv(shellPassPhraseEnvName, fileKeyringPassphrase)

	const valueToStore = `this password
	has multiple
	lines and will be
	encoded by some keyring implementiations
	like osx`

	err := Set("file", service, user, valueToStore)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// read the value after saved
	value, err := Get("file", service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if value != valueToStore {
		t.Errorf("Value set was %s but got: %s", valueToStore, value)
	}
}

func TestGetMultiLineForFileKeyring(t *testing.T) {
	// set pass phrase via shell
	os.Setenv(shellPassPhraseEnvName, fileKeyringPassphrase)

	const valueToStore = `this password
	has multiple
	lines and will be
	encoded by some keyring implementiations
	like osx`

	err := Set("file", service, user, valueToStore)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// read the value after saved
	value, err := Get("file", service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if value != valueToStore {
		t.Errorf("Value set was %s but got: %s", valueToStore, value)
	}
}

func TestDeleteFileKeyring(t *testing.T) {
	// set pass phrase via shell
	os.Setenv(shellPassPhraseEnvName, fileKeyringPassphrase)

	// save a key value first
	err := Set("file", service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// read the value after saved
	_, err = Get("file", service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	err = Delete("file", service, user)

	if err != nil {
		t.Error("Something went wrong when deleting from file keyring")
	}
}
