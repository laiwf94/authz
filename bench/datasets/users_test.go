package datasets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestUsersMatchTheGraph(t *testing.T) {
	g := mustSize(t, 20_000, 6)
	member := map[string]bool{}
	if err := g.Each(func(r *Relationship) error {
		if r.ResourceType == TypeGroup && r.SubjectType == TypeUser {
			member[r.String()] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	passwords := map[string]bool{}
	n := 0
	err := g.EachUser(g.Users, func(u User) error {
		if u.Username != ObjectID(TypeUser, n) || u.Email != u.Username+"@bench.example" || !strings.HasPrefix(u.Password, "pw-") || len(u.Password) != 23 {
			return errors.New("bad user " + u.Username)
		}
		if len(u.Groups) != groupsPerUser {
			return errors.New(u.Username + ": wrong group count")
		}
		for _, grp := range u.Groups {
			if !member["group:"+grp+"#member@user:"+u.Username] {
				return errors.New(u.Username + " is not a member of " + grp + " in the graph")
			}
		}
		if passwords[u.Password] {
			return errors.New("repeated password")
		}
		passwords[u.Password] = true
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != g.Users || len(member) != g.Users*groupsPerUser {
		t.Fatalf("%d users, %d memberships", n, len(member))
	}
	if u := g.User(17); u.Username != "u17" || u.Password != g.Password(17) {
		t.Errorf("User(17) = %+v", u)
	}
	other := g
	other.Seed++
	if other.Password(17) == g.Password(17) {
		t.Error("passwords do not depend on the seed")
	}
	for _, bad := range []int{-1, g.Users + 1} {
		if err := g.EachUser(bad, func(User) error { return nil }); err == nil {
			t.Errorf("EachUser(%d) accepted", bad)
		}
	}
	if err := (Graph{}).EachUser(0, func(User) error { return nil }); err == nil {
		t.Error("an empty graph's users accepted")
	}
}

func TestWriteUsers(t *testing.T) {
	g := mustSize(t, 5_000, 1)
	var js, creds bytes.Buffer
	if err := WriteUsers(&js, g, 50, FormatUsersJSON); err != nil {
		t.Fatal(err)
	}
	if err := WriteUsers(&creds, g, 50, FormatCredentials); err != nil {
		t.Fatal(err)
	}
	sj, sc := bufio.NewScanner(&js), bufio.NewScanner(&creds)
	i := 0
	for sj.Scan() && sc.Scan() {
		var u User
		if err := json.Unmarshal(sj.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		if want := g.User(i); u.Username != want.Username || u.Password != want.Password || strings.Join(u.Groups, ",") != strings.Join(want.Groups, ",") {
			t.Fatalf("line %d: %+v", i, u)
		}
		if sc.Text() != u.Username+":"+u.Password {
			t.Fatalf("credentials line %d does not match the user", i)
		}
		i++
	}
	if i != 50 {
		t.Fatalf("%d users written", i)
	}
	if err := WriteUsers(&js, g, 1, "xml"); err == nil {
		t.Error("unknown format accepted")
	}
	if err := WriteUsers(failWriter{}, g, 10, FormatCredentials); err == nil {
		t.Error("a write error was hidden")
	}
}

func TestUserGroupsAndManifest(t *testing.T) {
	g := mustSize(t, 10_000, 4)
	got := g.UserGroups(3, []int{99})
	u := g.User(3)
	if len(got) != 1+groupsPerUser || got[0] != 99 || ObjectID(TypeGroup, got[1]) != u.Groups[0] || ObjectID(TypeGroup, got[2]) != u.Groups[1] {
		t.Errorf("UserGroups(3) = %v, User(3).Groups = %v", got, u.Groups)
	}
	m := g.Describe()
	if m.Relationships != g.Count() || m.Graph != g || m.Shape.GroupsPerUser != groupsPerUser || len(m.BenchFlags) != 16 {
		t.Errorf("manifest %+v", m)
	}
	if (LoadResult{}).PerSecond() != 0 {
		t.Error("an empty load has a rate")
	}
}
