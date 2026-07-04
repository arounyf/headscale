package derp

import (
	"net/url"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
)

func TestGetDERPMap_BothURLAndPath(t *testing.T) {
	u, _ := url.Parse("https://controlplane.tailscale.com/derpmap/default")
	cfg := types.DERPConfig{
		URLs:  []url.URL{*u},
		Paths: []string{"/tmp/test-derp.yaml"},
	}

	dm, err := GetDERPMap(cfg)
	if err != nil {
		t.Fatal("GetDERPMap failed:", err)
	}

	hasTailscale := false
	hasCustom := false
	for _, r := range dm.Regions {
		if r.RegionCode == "nyc" {
			hasTailscale = true
		}
		if r.RegionCode == "test-derp" {
			hasCustom = true
		}
	}
	if !hasTailscale {
		t.Error("Tailscale regions missing")
	}
	if !hasCustom {
		t.Error("Custom region missing")
	}
	t.Logf("Total regions: %d", len(dm.Regions))
}
