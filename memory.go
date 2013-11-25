package yuuup

import "errors"

type MemoryKeyStore struct {
	Data map[string]*StoredKey
}

func (store *MemoryKeyStore) Lookup(userId []byte) (*StoredKey, error) {
	if key, ok := store.Data[string(userId)]; ok {
		return key, nil
	}

	return nil, errors.New("Not found")
}

func (store *MemoryKeyStore) Update(userId []byte, values *YubiKeyValues) error {
	if key, ok := store.Data[string(userId)]; ok {
		key.Val = *values
		return nil
	}

	return errors.New("Not found")
}

func (store *MemoryKeyStore) Insert(publicId string, aesKey, privateId []byte) error {
	store.Data[publicId] = &StoredKey{aesKey, privateId, YubiKeyValues{-1, -1, -1, -1}}
	return nil
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{make(map[string]*StoredKey)}
}
