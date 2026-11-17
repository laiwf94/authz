package store

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/laiwf94/authz/internal/authz/schema"
)

// MaxCaveatContextSize bounds the context stored with one relationship, in
// bytes of its JSON encoding.
const MaxCaveatContextSize = 4096

// Caveat names the schema caveat a relationship carries and the context
// stored with it. The relationship grants only where the caveat's
// expression is true for this context merged with the context a check
// supplies; values stored here take precedence.
//
// The store keeps the context in the form encoding/json gives it with
// numbers as json.Number, so a context reads back the same before and
// after a restart and large integers keep every digit. A Caveat returned
// by the store is shared and must not be modified.
type Caveat struct {
	Name    string         `json:"name"`
	Context map[string]any `json:"context,omitempty"`
}

// UnmarshalJSON decodes numbers in the context as json.Number.
func (c *Caveat) UnmarshalJSON(b []byte) error {
	var raw struct {
		Name    string          `json:"name"`
		Context json.RawMessage `json:"context"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	ctx, err := decodeContext(raw.Context)
	if err != nil {
		return err
	}
	*c = Caveat{Name: raw.Name, Context: ctx}
	return nil
}

// decodeContext decodes a JSON object with numbers as json.Number; null or
// nothing is no context.
func decodeContext(b []byte) (map[string]any, error) {
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var ctx map[string]any
	if err := d.Decode(&ctx); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("caveat context has data after the object")
	}
	if len(ctx) == 0 {
		return nil, nil
	}
	return ctx, nil
}

// caveatVal is a normalised caveat with its identity: two versions carry
// the same caveat exactly when their keys are equal.
type caveatVal struct {
	c   *Caveat
	key string // name, NUL, canonical JSON of the context
}

// normalizeCaveat validates c's syntax and size and returns it in the
// stored form: the context encoded and decoded again, so native Go values
// become what a recovered log holds, and an empty context becomes none.
// nil is no caveat.
func normalizeCaveat(c *Caveat) (*caveatVal, error) {
	if c == nil {
		return nil, nil
	}
	if !typeRe.MatchString(c.Name) {
		return nil, invalid("caveat name %q is not a valid name", c.Name)
	}
	enc := []byte("null")
	if len(c.Context) > 0 {
		var err error
		if enc, err = json.Marshal(c.Context); err != nil {
			return nil, invalid("caveat %s context: %v", c.Name, err)
		}
	}
	if len(enc) > MaxCaveatContextSize {
		return nil, invalid("caveat %s context is %d bytes encoded (max %d)", c.Name, len(enc), MaxCaveatContextSize)
	}
	ctx, err := decodeContext(enc)
	if err != nil {
		return nil, invalid("caveat %s context: %v", c.Name, err)
	}
	if ctx != nil {
		// Encoding a decoded context gives canonical JSON: sorted keys and
		// numbers exactly as written.
		if enc, err = json.Marshal(ctx); err != nil {
			return nil, invalid("caveat %s context: %v", c.Name, err)
		}
	}
	return &caveatVal{c: &Caveat{Name: c.Name, Context: ctx}, key: c.Name + "\x00" + string(enc)}, nil
}

func (v *caveatVal) caveat() *Caveat {
	if v == nil {
		return nil
	}
	return v.c
}

func (v *caveatVal) id() string {
	if v == nil {
		return ""
	}
	return v.key
}

// CheckStored is CheckAgainst for a relationship with a caveat (nil for
// none): the relation must list the subject type with that caveat, and the
// caveat must be declared and accept the stored context.
func CheckStored(sc *schema.Schema, r Relationship, c *Caveat) error {
	return checkAgainstCaveat(sc, r, c)
}

func checkAgainstCaveat(sc *schema.Schema, r Relationship, c *Caveat) error {
	if c == nil {
		return checkAgainst(sc, r)
	}
	cv, ok := sc.Caveats[c.Name]
	if !ok {
		return invalid("caveat %q is not defined in the schema", c.Name)
	}
	if err := checkAllows(sc, r, c.Name); err != nil {
		return err
	}
	if err := cv.ValidateContext(c.Context); err != nil {
		return invalid("%s: %v", r, err)
	}
	return nil
}
