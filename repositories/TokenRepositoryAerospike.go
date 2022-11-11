package repositories

import (
	as "github.com/aerospike/aerospike-client-go"
)

type TokenRepositoryAerospike struct {
	client    *as.Client
	namespace string
	setName   string
}

func NewTokenRepositoryAerospike(aerospikeHost string, aerospikePort int, namespace, setName string) (*TokenRepositoryAerospike, error) {
	client, err := as.NewClient(aerospikeHost, aerospikePort)

	if err != nil {
		return nil, err
	}

	return &TokenRepositoryAerospike{
		client:    client,
		namespace: namespace,
		setName:   setName,
	}, nil
}

func (t *TokenRepositoryAerospike) AddToken(token string, seconds uint32) bool {

	key, _ := as.NewKey(t.namespace, t.setName, token)
	bin := as.NewBin("F", 1)

	err := t.client.AddBins(as.NewWritePolicy(0, seconds), key, bin)

	return err != nil
}

func (t *TokenRepositoryAerospike) IsSet(token string) bool {

	key, _ := as.NewKey(t.namespace, t.setName, token)

	_, err := t.client.Get(as.NewPolicy(), key)

	return err == nil
}
