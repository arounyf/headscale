package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func TestAutogroupSelfCache_Hit(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
	}
	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[0]), IPv4: ap("100.64.0.3")},
	}

	policy2 := &Policy{ACLs: []ACL{{Action: "accept",
		Sources:      []Alias{agp("autogroup:member")},
		Destinations: []AliasWithPorts{aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny)},
	}}}
	if err := policy2.validate(); err != nil {
		t.Fatal(err)
	}

	nodesSlice := nodes.ViewSlice()
	pm := &PolicyManager{
		pol: policy2, users: []types.User{users[0]}, nodes: nodesSlice,
	}
	_, _ = pm.updateLocked()

	// Node 0 populates cache
	r0 := pm.filterRulesForNodeLocked(nodesSlice.At(0))
	c0 := len(pm.autogroupSelfCache)
	if c0 == 0 {
		t.Fatal("cache should have entries after first call")
	}

	// Node 1 (same user) hits cache
	r1 := pm.filterRulesForNodeLocked(nodesSlice.At(1))
	c1 := len(pm.autogroupSelfCache)
	if c1 != c0 {
		t.Errorf("same-user should hit cache: %d != %d", c0, c1)
	}

	// Node 2 (same user) hits cache
	r2 := pm.filterRulesForNodeLocked(nodesSlice.At(2))
	c2 := len(pm.autogroupSelfCache)
	if c2 != c0 {
		t.Errorf("same-user should hit cache: %d != %d", c0, c2)
	}

	// Same rules for same user
	if len(r0) != len(r1) || len(r1) != len(r2) {
		t.Error("same-user nodes should get identical rules")
	}
	t.Logf("PASS: %d cache entries for 3 nodes of same user", c2)
}

func TestAutogroupSelfCache_UserIsolation(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}
	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[1]), IPv4: ap("100.64.0.2")},
	}

	policy2 := &Policy{ACLs: []ACL{{Action: "accept",
		Sources:      []Alias{agp("autogroup:member")},
		Destinations: []AliasWithPorts{aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny)},
	}}}
	if err := policy2.validate(); err != nil {
		t.Fatal(err)
	}

	nodesSlice := nodes.ViewSlice()
	pm := &PolicyManager{
		pol: policy2, users: []types.User{users[0], users[1]}, nodes: nodesSlice,
	}
	_, _ = pm.updateLocked()

	// User1
	pm.filterRulesForNodeLocked(nodesSlice.At(0))
	c1 := len(pm.autogroupSelfCache)
	// User2
	pm.filterRulesForNodeLocked(nodesSlice.At(1))
	c2 := len(pm.autogroupSelfCache)

	if c2 <= c1 {
		t.Errorf("different users should add entries: %d <= %d", c2, c1)
	}
	t.Logf("PASS: %d cache entries for 2 users", c2)
}

func TestAutogroupSelfCache_ClearedOnPolicyChange(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "user1"}}
	nodes := types.Nodes{{User: new(users[0]), IPv4: ap("100.64.0.1")}}

	policy2 := &Policy{ACLs: []ACL{{Action: "accept",
		Sources:      []Alias{agp("autogroup:member")},
		Destinations: []AliasWithPorts{aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny)},
	}}}
	if err := policy2.validate(); err != nil {
		t.Fatal(err)
	}

	nodesSlice := nodes.ViewSlice()
	pm := &PolicyManager{
		pol: policy2, users: []types.User{users[0]}, nodes: nodesSlice,
	}
	_, _ = pm.updateLocked()

	pm.filterRulesForNodeLocked(nodesSlice.At(0))
	if len(pm.autogroupSelfCache) == 0 {
		t.Fatal("cache should have entries")
	}

	// Reload policy
	_, err := pm.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pm.autogroupSelfCache) != 0 {
		t.Errorf("cache should be cleared on policy change, got %d", len(pm.autogroupSelfCache))
	}
	t.Log("PASS: cache cleared on policy change")
}
