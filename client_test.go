package tpmops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStoredKeyJSONRoundtrip(t *testing.T) {
	sk := StoredKey{
		Private: []byte("privblob"),
		Public:  []byte("pubblob"),
	}

	b, err := json.Marshal(sk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got StoredKey
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(got.Private) != "privblob" || string(got.Public) != "pubblob" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestLoadKeyFromFile_FileMissing(t *testing.T) {
	c := &TPMClient{}
	_, err := c.LoadKeyFromFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoadKeyFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := &TPMClient{}
	_, err := c.LoadKeyFromFile(p)
	if err == nil {
		t.Fatalf("expected error for invalid json")
	}
}

func TestLoadKey_InvalidBlobs(t *testing.T) {
	c := &TPMClient{}
	// Provide bytes that are not valid TPM marshalling – Unmarshal should fail.
	_, err := c.LoadKey([]byte("badpriv"), []byte("badpub"))
	if err == nil {
		t.Fatalf("expected unmarshal error for invalid blobs")
	}
}
