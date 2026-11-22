package datasets

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// User is one account of the sign-in population: the graph's user:u<n>,
// with the groups it is a direct member of in the graph, so a provider's
// group claims and the relationships agree.
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
}

// Password is user n's password: 20 hex digits derived from the seed. The
// passwords are public by construction, like the rest of the dataset; they
// exist so every provider in the benchmark signs in the same accounts.
func (g Graph) Password(n int) string {
	var in [17]byte
	binary.BigEndian.PutUint64(in[:8], g.Seed)
	binary.BigEndian.PutUint64(in[8:16], uint64(n))
	in[16] = byte(kindPassword)
	sum := sha256.Sum256(in[:])
	return "pw-" + hex.EncodeToString(sum[:10])
}

// User returns user n of the population.
func (g Graph) User(n int) User {
	return g.user(g.newStream(), n, nil)
}

func (g Graph) user(s *stream, n int, groups []int) User {
	id := ObjectID(TypeUser, n)
	u := User{Username: id, Password: g.Password(n), Email: id + "@bench.example", Name: "Bench User " + strconv.Itoa(n)}
	for _, x := range g.userGroups(s, n, groups[:0]) {
		u.Groups = append(u.Groups, ObjectID(TypeGroup, x))
	}
	return u
}

// EachUser calls fn for users 0..n-1, in order. n must be at most
// g.Users: the population signs in users that exist in the graph.
func (g Graph) EachUser(n int, fn func(User) error) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if n < 0 || n > g.Users {
		return fmt.Errorf("users: %d, want 0 to the graph's %d", n, g.Users)
	}
	s := g.newStream()
	groups := make([]int, 0, groupsPerUser)
	for i := range n {
		if err := fn(g.user(s, i, groups)); err != nil {
			return err
		}
	}
	return nil
}

// Output formats of WriteUsers.
const (
	// FormatUsersJSON is one User as JSON per line, for provider setups to
	// turn into their own import formats.
	FormatUsersJSON = "json"
	// FormatCredentials is USER:PASSWORD per line, authzbench's
	// -login-credentials @FILE.
	FormatCredentials = "credentials"
)

// WriteUsers writes users 0..n-1 to w in format.
func WriteUsers(w io.Writer, g Graph, n int, format string) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	var line func(User) error
	switch format {
	case FormatUsersJSON:
		line = func(u User) error { return enc.Encode(u) }
	case FormatCredentials:
		line = func(u User) error {
			_, err := fmt.Fprintf(bw, "%s:%s\n", u.Username, u.Password)
			return err
		}
	default:
		return fmt.Errorf("format %q: want %s or %s", format, FormatUsersJSON, FormatCredentials)
	}
	if err := g.EachUser(n, line); err != nil {
		return err
	}
	return bw.Flush()
}
