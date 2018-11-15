// Package digests collects common hash algorithms
// collections.
package digests

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

//Algorithm is the type of hash algorithm
type Algorithm = string

const (
	//MD5 hash
	MD5 Algorithm = "md5"
	//SHA1 hash
	SHA1 Algorithm = "sha1"
	//SHA224 hash
	SHA224 Algorithm = "sha224"
	//SHA256 hash
	SHA256 Algorithm = "sha256"
	//SHA384 hash
	SHA384 Algorithm = "sha384"
	//SHA512 hash
	SHA512 Algorithm = "sha512"
	//SHA512224 hash
	SHA512224 Algorithm = "sha512/224"
	//SHA512256 hash
	SHA512256 Algorithm = "sha512/256"
)
const (
	//NotSupported algorithm not supported
	NotSupported = "Hash Algorithm not supported "
	//NotInRegistry algotihm not found
	NotInRegistry = "Hash algorithm not in registry "
)

//A Digest represents the result of computing a hash
type Digest struct {
	Algorithm Algorithm // algorithm used to generate the digest
	Hash      []byte    // output of the hash algorithm
}

// Merge performs a union of two digest lists
func Merge(l1 []Digest, l2 []Digest) []Digest {

	combined := make([]Digest, len(l1))
	for i, d1 := range l1 {
		combined[i] = d1
	}

	for _, d2 := range l2 {
		found := false
		for _, d1 := range l1 {
			if bytes.Equal(d1.Hash, d2.Hash) {
				found = true
			}
		}

		if !found {
			combined = append(combined, d2)
		}

	}
	return combined
}

// String hex encodes the digest value
func (d Digest) String() string {
	return hex.EncodeToString(d.Hash)
}

// Digester is the interface used to compute digests
type Digester interface {
	GetDigestFunction(Algorithm) (DigestFunction, error)
	ComputeEnabledDigests([]byte) Computed
}

//Computed represents all the digests computed for a given
//item based on the enabled hash functions
type Computed struct {
	Digests            []Digest //computed digests
	PrimaryDigestIndex uint     //index into computed digests of the configured primary algorithm
}

// PrimaryDigest returns digest for the configured primary hash algorithm
// if the primary index is invalid, it will return an error
func (c *Computed) PrimaryDigest() (Digest, error) {
	if c.PrimaryDigestIndex > uint(len(c.Digests)) {
		return Digest{}, errors.New("invalid primary digest index")
	}
	return c.Digests[c.PrimaryDigestIndex], nil
}

//Computer capable of computing digests for
//registered algorithms
type Computer struct {
	registry    map[Algorithm]DigestFunction
	primaryAlgo Algorithm
}

// DigestFunction is a function that computes the digest
type DigestFunction func([]byte) Digest

var supportedAlgorithms = map[Algorithm]DigestFunction{

	MD5: func(data []byte) Digest {
		h := md5.Sum(data)
		return Digest{MD5, h[:]}
	},
	SHA1: func(data []byte) Digest {
		h := sha1.Sum(data)
		return Digest{SHA1, h[:]}
	},
	SHA224: func(data []byte) Digest {
		h := sha256.Sum224(data)
		return Digest{SHA224, h[:]}
	},
	SHA256: func(data []byte) Digest {
		h := sha256.Sum256(data)
		return Digest{SHA256, h[:]}
	},
	SHA384: func(data []byte) Digest {
		h := sha512.Sum384(data)
		return Digest{SHA384, h[:]}
	},
	SHA512: func(data []byte) Digest {
		h := sha512.Sum512(data)
		return Digest{SHA512, h[:]}
	},
	SHA512224: func(data []byte) Digest {
		h := sha512.Sum512_224(data)
		return Digest{SHA512224, h[:]}
	},
	SHA512256: func(data []byte) Digest {
		h := sha512.Sum512_224(data)
		return Digest{SHA512256, h[:]}
	},
}

//NewComputer creates a new Computer that will compute digests for
//only the provided algorithms
func NewComputer(primaryAlgo Algorithm, algos []Algorithm) *Computer {
	logger := log.WithFields(log.Fields{"func": "NewComputer"})

	registry := make(map[Algorithm]DigestFunction)
	for _, a := range algos {
		canon := strings.ToLower(a)
		df, ok := supportedAlgorithms[canon]
		if !ok {
			logger.Fatal(NotSupported, a)
		}
		registry[canon] = df
	}

	canonPrimary := strings.ToLower(primaryAlgo)
	df, ok := supportedAlgorithms[canonPrimary]
	if !ok {
		logger.Fatal(NotSupported, df)
	}
	registry[canonPrimary] = df

	return &Computer{
		registry:    registry,
		primaryAlgo: canonPrimary,
	}
}

//GetDigestFunction returns the function to perform a hash for the given
//algorithm
func (d *Computer) GetDigestFunction(algo Algorithm) (DigestFunction, error) {
	val, ok := d.registry[algo]
	if !ok {
		return nil, errors.New(NotInRegistry)
	}
	return val, nil
}

//ComputeEnabledDigests will execute the enabled hash functions on
//the given data and return the computed digests
func (d *Computer) ComputeEnabledDigests(data []byte) Computed {
	ch := make(chan Digest, len(d.registry))
	for _, df := range d.registry {
		go func(f DigestFunction) {
			ch <- f(data)
		}(df)
	}

	var primary uint
	digests := make([]Digest, len(d.registry))
	for i := 0; i < len(d.registry); i++ {
		digest := <-ch
		digests[i] = digest
		//Check if primary
		if digest.Algorithm == d.primaryAlgo {
			primary = uint(i)
		}
	}
	return Computed{digests, primary}
}
