// Package store holds relationships in a multi-version store with a
// write-ahead log, so every read can be served at a consistent snapshot.
package store

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Relationship says that Subject has Relation on Resource, for example
// document:readme#viewer@user:alice or folder:docs#viewer@group:eng#member.
type Relationship struct {
	ResourceType    string `json:"resource_type"`
	ResourceID      string `json:"resource_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation,omitempty"`
}

var (
	typeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_\-=.+/|]{1,128}$`)
)

// ValidID reports whether s is a valid object ID. "*" is not an object ID;
// it is only allowed as a wildcard subject.
func ValidID(s string) bool { return idRe.MatchString(s) && s != "*" }

// ErrInvalid wraps every validation failure for relationships and filters.
var ErrInvalid = errors.New("invalid argument")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate checks the syntax of every field. Schema rules are checked by the
// caller, which owns the schema.
func (r Relationship) Validate() error {
	switch {
	case !typeRe.MatchString(r.ResourceType):
		return invalid("resource type %q is not a valid name", r.ResourceType)
	case !ValidID(r.ResourceID):
		return invalid("resource id %q is not valid (1-128 of A-Z a-z 0-9 _ - = . + / |)", r.ResourceID)
	case !typeRe.MatchString(r.Relation):
		return invalid("relation %q is not a valid name", r.Relation)
	case !typeRe.MatchString(r.SubjectType):
		return invalid("subject type %q is not a valid name", r.SubjectType)
	case r.SubjectID != "*" && !ValidID(r.SubjectID):
		return invalid("subject id %q is not valid", r.SubjectID)
	case r.SubjectRelation != "" && !typeRe.MatchString(r.SubjectRelation):
		return invalid("subject relation %q is not a valid name", r.SubjectRelation)
	case r.SubjectID == "*" && r.SubjectRelation != "":
		return invalid("a wildcard subject cannot have a relation")
	}
	return nil
}

// String renders the canonical text form.
func (r Relationship) String() string {
	return r.ResourceType + ":" + r.ResourceID + "#" + r.Relation + "@" + r.Subject().String()
}

// Subject returns the relationship's subject.
func (r Relationship) Subject() Subject {
	return Subject{Type: r.SubjectType, ID: r.SubjectID, Relation: r.SubjectRelation}
}

// Subject is a user or a userset such as group:eng#member.
type Subject struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation,omitempty"`
}

func (s Subject) String() string {
	if s.Relation != "" {
		return s.Type + ":" + s.ID + "#" + s.Relation
	}
	return s.Type + ":" + s.ID
}

// Validate checks subject syntax; wildcard subjects are rejected because a
// check is always about a concrete subject.
func (s Subject) Validate() error {
	switch {
	case !typeRe.MatchString(s.Type):
		return invalid("subject type %q is not a valid name", s.Type)
	case !ValidID(s.ID):
		return invalid("subject id %q is not valid", s.ID)
	case s.Relation != "" && !typeRe.MatchString(s.Relation):
		return invalid("subject relation %q is not a valid name", s.Relation)
	}
	return nil
}

// ParseRelationship parses "type:id#relation@subjecttype:subjectid[#relation]".
func ParseRelationship(s string) (Relationship, error) {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return Relationship{}, invalid("relationship %q has no '@'", s)
	}
	res, sub := s[:at], s[at+1:]
	hash := strings.LastIndexByte(res, '#')
	if hash < 0 {
		return Relationship{}, invalid("relationship %q has no '#relation'", s)
	}
	rt, rid, ok := strings.Cut(res[:hash], ":")
	if !ok {
		return Relationship{}, invalid("resource %q must be type:id", res[:hash])
	}
	subj, err := ParseSubject(sub, true)
	if err != nil {
		return Relationship{}, err
	}
	r := Relationship{ResourceType: rt, ResourceID: rid, Relation: res[hash+1:],
		SubjectType: subj.Type, SubjectID: subj.ID, SubjectRelation: subj.Relation}
	return r, r.Validate()
}

// ParseSubject parses "type:id" or "type:id#relation". allowWildcard permits
// "type:*".
func ParseSubject(s string, allowWildcard bool) (Subject, error) {
	t, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Subject{}, invalid("subject %q must be type:id", s)
	}
	id, rel := rest, ""
	if h := strings.LastIndexByte(rest, '#'); h >= 0 {
		id, rel = rest[:h], rest[h+1:]
		if rel == "" {
			return Subject{}, invalid("subject %q has an empty relation after '#'", s)
		}
	}
	subj := Subject{Type: t, ID: id, Relation: rel}
	if id == "*" {
		if !allowWildcard {
			return Subject{}, invalid("wildcard subject %q is not allowed here", s)
		}
		if rel != "" {
			return Subject{}, invalid("a wildcard subject cannot have a relation")
		}
		if !typeRe.MatchString(t) {
			return Subject{}, invalid("subject type %q is not a valid name", t)
		}
		return subj, nil
	}
	return subj, subj.Validate()
}
