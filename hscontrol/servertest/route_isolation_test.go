package servertest_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const routeIsoTimeout = 15 * time.Second

// TestMultiTenantRouteIsolation verifies the core multi-tenant guarantee:
// user A's nodes cannot see subnet routes from user B's routers, and
// vice versa. Routes are scoped per-user via per-user primary routes.
func TestMultiTenantRouteIsolation(t *testing.T) {
	srv := servertest.NewServer(t)

	// ── Users ──
	userA := srv.CreateUser(t, "tenant-a")
	userB := srv.CreateUser(t, "tenant-b")

	// ── User A: one router + one regular node ──
	aRouter := servertest.NewClient(t, srv, "a-router", servertest.WithUser(userA))
	aNode := servertest.NewClient(t, srv, "a-node", servertest.WithUser(userA))

	// ── User B: one router + one regular node ──
	bRouter := servertest.NewClient(t, srv, "b-router", servertest.WithUser(userB))
	bNode := servertest.NewClient(t, srv, "b-node", servertest.WithUser(userB))

	// Wait for full mesh
	aRouter.WaitForPeers(t, 3, routeIsoTimeout)
	aNode.WaitForPeers(t, 3, routeIsoTimeout)
	bRouter.WaitForPeers(t, 3, routeIsoTimeout)
	bNode.WaitForPeers(t, 3, routeIsoTimeout)

	// ── Advertise and approve routes ──
	routeA := netip.MustParsePrefix("10.42.0.0/24")
	routeB := netip.MustParsePrefix("10.43.0.0/24")

	advertiseAndApproveRoute(t, srv, aRouter, routeA)
	advertiseAndApproveRoute(t, srv, bRouter, routeB)

	// ── Server-side checks: RoutesForPeer ──

	aRouterID := findNodeID(t, srv, "a-router")
	aNodeID := findNodeID(t, srv, "a-node")
	bRouterID := findNodeID(t, srv, "b-router")
	bNodeID := findNodeID(t, srv, "b-node")

	aRouterView, _ := srv.State().GetNodeByID(aRouterID)
	aNodeView, _ := srv.State().GetNodeByID(aNodeID)
	bRouterView, _ := srv.State().GetNodeByID(bRouterID)
	bNodeView, _ := srv.State().GetNodeByID(bNodeID)

	// Get real matchers from the policy engine (default DB mode allows all)
	aNodeMatchers, _ := srv.State().MatchersForNode(aNodeView)
	bNodeMatchers, _ := srv.State().MatchersForNode(bNodeView)

	t.Run("same-user sees own routes", func(t *testing.T) {
		// a-node looking at a-router: should see 10.42.0.0/24
		routes := srv.State().RoutesForPeer(aNodeView, aRouterView, aNodeMatchers)
		require.True(t, slices.Contains(routes, routeA),
			"a-node should see a-router's route %s, got %v", routeA, routes)

		// b-node looking at b-router: should see 10.43.0.0/24
		routes = srv.State().RoutesForPeer(bNodeView, bRouterView, bNodeMatchers)
		require.True(t, slices.Contains(routes, routeB),
			"b-node should see b-router's route %s, got %v", routeB, routes)
	})

	t.Run("cross-user route isolation", func(t *testing.T) {
		// a-node looking at b-router: should NOT see 10.43.0.0/24
		routes := srv.State().RoutesForPeer(aNodeView, bRouterView, aNodeMatchers)
		require.False(t, slices.Contains(routes, routeB),
			"a-node should NOT see b-router's route %s (cross-tenant leak!), got %v", routeB, routes)

		// b-node looking at a-router: should NOT see 10.42.0.0/24
		routes = srv.State().RoutesForPeer(bNodeView, aRouterView, bNodeMatchers)
		require.False(t, slices.Contains(routes, routeA),
			"b-node should NOT see a-router's route %s (cross-tenant leak!), got %v", routeA, routes)
	})

	// Note: client-side netmap verification is covered by existing
	// integration tests. Server-side RoutesForPeer checks above
	// directly validate the multi-tenant route isolation boundary.
}

// TestPerUserPrimaryRoutes_HAFailover verifies that HA failover operates
// within a user scope: when the primary for a prefix goes offline, a
// second router from the SAME user takes over.
func TestPerUserPrimaryRoutes_HAFailover(t *testing.T) {
	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "tenant")

	r1 := servertest.NewClient(t, srv, "r1", servertest.WithUser(user))
	r2 := servertest.NewClient(t, srv, "r2", servertest.WithUser(user))

	r1.WaitForPeers(t, 1, routeIsoTimeout)
	r2.WaitForPeers(t, 1, routeIsoTimeout)

	route := netip.MustParsePrefix("10.99.0.0/24")
	r1ID := advertiseAndApproveRoute(t, srv, r1, route)
	r2ID := advertiseAndApproveRoute(t, srv, r2, route)

	// Low-ID wins primary
	primaries := srv.State().GetNodePrimaryRoutes(r1ID)
	require.True(t, slices.Contains(primaries, route),
		"r1 (lower ID) should be primary for %s, got %v", route, primaries)

	r2Primaries := srv.State().GetNodePrimaryRoutes(r2ID)
	require.False(t, slices.Contains(r2Primaries, route),
		"r2 should NOT be primary while r1 is healthy")

	// Take r1 offline
	r1.Disconnect(t)

	// Wait for r2 to become primary (poll until election runs)
	require.Eventually(t, func() bool {
		p := srv.State().GetNodePrimaryRoutes(r2ID)
		return slices.Contains(p, route)
	}, routeIsoTimeout, 200*time.Millisecond,
		"r2 should become primary after r1 disconnects")

	r1Primaries := srv.State().GetNodePrimaryRoutes(r1ID)
	require.False(t, slices.Contains(r1Primaries, route),
		"offline r1 should no longer be primary")
}

// TestPerUserPrimaryRoutes_ExitRouteUnaffected verifies that exit routes
// (0.0.0.0/0, ::/0) are excluded from primary election regardless of
// per-user scoping — they are not subject to HA failover.
func TestPerUserPrimaryRoutes_ExitRouteUnaffected(t *testing.T) {
	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "tenant")

	c := servertest.NewClient(t, srv, "exit-router", servertest.WithUser(user))
	c.WaitForPeers(t, 0, routeIsoTimeout)

	exitV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitV6 := netip.MustParsePrefix("::/0")

	c.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-exit",
		Hostname:     "exit-router",
		RoutableIPs:  []netip.Prefix{exitV4, exitV6},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Direct().SendUpdate(ctx)

	nodeID := findNodeID(t, srv, "exit-router")

	// Approve both exit routes
	_, rc, err := srv.State().SetApprovedRoutes(nodeID, []netip.Prefix{exitV4, exitV6})
	require.NoError(t, err)
	srv.App.Change(rc)

	// Exit routes should NOT appear in primary routes
	primaries := srv.State().GetNodePrimaryRoutes(nodeID)
	require.False(t, slices.Contains(primaries, exitV4),
		"0.0.0.0/0 should not be elected as primary route")
	require.False(t, slices.Contains(primaries, exitV6),
		"::/0 should not be elected as primary route")
}
