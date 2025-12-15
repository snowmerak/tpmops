package tpmops

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/dgraph-io/badger/v4"
)

var ErrKeyNotFound = fmt.Errorf("key not found")

type Store interface {
	SaveKey(keyName string, sk StoredKey) error
	LoadKey(keyName string) (StoredKey, error)
	Close() error
}

type BadgerStore struct {
	db *badger.DB
}

func NewBadgerDB(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir)
	// Reduce logging noise for library usage
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("opening BadgerDB: %w", err)
	}

	return &BadgerStore{db: db}, nil
}

func (s *BadgerStore) SaveKey(keyName string, sk StoredKey) error {
	data, err := json.Marshal(sk)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(keyName), data)
	})
}

func (s *BadgerStore) LoadKey(keyName string) (StoredKey, error) {
	var sk StoredKey
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(keyName))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &sk)
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return StoredKey{}, ErrKeyNotFound
		}
		return StoredKey{}, fmt.Errorf("loading key from BadgerDB: %w", err)
	}

	return sk, nil
}

func (s *BadgerStore) Close() error {
	return s.db.Close()
}

type PebbleStore struct {
	db *pebble.DB
}

func NewPebbleDB(dir string) (*PebbleStore, error) {
	opts := &pebble.Options{}
	db, err := pebble.Open(dir, opts)
	if err != nil {
		return nil, fmt.Errorf("opening PebbleDB: %w", err)
	}

	return &PebbleStore{db: db}, nil
}

func (s *PebbleStore) SaveKey(keyName string, sk StoredKey) error {
	data, err := json.Marshal(sk)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}
	// Pebble Set is synchronous by default with Sync option, or we can use NoSync for speed.
	// For keys, safety is preferred.
	return s.db.Set([]byte(keyName), data, pebble.Sync)
}

func (s *PebbleStore) LoadKey(keyName string) (StoredKey, error) {
	val, closer, err := s.db.Get([]byte(keyName))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return StoredKey{}, ErrKeyNotFound
		}
		return StoredKey{}, fmt.Errorf("loading key from PebbleDB: %w", err)
	}
	defer closer.Close()

	var sk StoredKey
	if err := json.Unmarshal(val, &sk); err != nil {
		return StoredKey{}, fmt.Errorf("unmarshaling key: %w", err)
	}
	return sk, nil
}

func (s *PebbleStore) Close() error {
	return s.db.Close()
}
