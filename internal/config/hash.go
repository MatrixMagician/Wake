package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Hash returns a stable content hash of the effective configuration,
// recorded in every snapshot manifest (SPEC.md §2 goal 5) so a reader can
// tell whether two snapshots were taken under the same configuration
// without diffing the whole file.
//
// Stability contract: Hash is deterministic across processes and Go
// versions for the same field values — it marshals through
// encoding/json (whose map key ordering and struct field ordering are both
// well-defined) rather than hashing a Go-internal representation like
// fmt.Sprintf("%#v", ...), which is not a stability contract Go makes.
// Changing this function changes every future config hash; that is fine,
// but do it deliberately and note it, since Sift may key on it.
func (c *Config) Hash() string {
	// Errors are impossible here: Config contains no channels, funcs, or
	// cyclic structures, only the plain data types declared in this
	// package. A marshal failure would be a programming error, not a
	// runtime condition callers need to handle, so we fail loudly rather
	// than return a bogus hash of an empty payload.
	b, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Sprintf("config: Hash: Config must always be JSON-marshalable: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
