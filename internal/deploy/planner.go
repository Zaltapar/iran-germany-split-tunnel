package deploy

import (
	"fmt"
	"reflect"
)

// PlanDesired compares the current manifest with desired state without any
// filesystem, process, service, or firewall side effects.
func PlanDesired(current *Manifest, desired DesiredState) (Plan, error) {
	if desired.Role != RoleIran && desired.Role != RoleGermany {
		return Plan{}, fmt.Errorf("%w: desired role", ErrInvalidManifest)
	}
	if current != nil && current.Role != desired.Role {
		return Plan{}, fmt.Errorf("%w: role cannot change in place", ErrInvalidManifest)
	}
	var changes []Change
	if current == nil {
		changes = append(changes, Change{Field: "install", After: desired.Role})
	} else {
		compare := func(field, before, after string, destructive bool) {
			if before != after {
				changes = append(changes, Change{Field: field, Before: before, After: after, Destructive: destructive})
			}
		}
		compare("components.splitter.version", current.Components.Splitter.Version, desired.Components.Splitter.Version, false)
		compare("components.xray.version", current.Components.Xray.Version, desired.Components.Xray.Version, false)
		compare("components.origin.mode", current.Components.Origin.Mode, desired.Components.Origin.Mode, true)
		compare("components.origin.domain", current.Components.Origin.Domain, desired.Components.Origin.Domain, true)
		compare("paths.env", current.Paths.Env, desired.Paths.Env, true)
		compare("paths.config", current.Paths.Config, desired.Paths.Config, true)
		compare("firewall.backend", current.Firewall.Backend, desired.Firewall.Backend, true)
		compare("firewall.ownership", current.Firewall.Ownership, desired.Firewall.Ownership, true)
		compare("firewall.rulesHash", current.Firewall.RulesHash, desired.Firewall.RulesHash, true)
		compare("pairing.state", current.Pairing.State, desired.Pairing.State, true)
		if !reflect.DeepEqual(current.Services, desired.Services) {
			changes = append(changes, Change{Field: "services", Before: fmt.Sprintf("%d", len(current.Services)), After: fmt.Sprintf("%d", len(desired.Services)), Destructive: true})
		}
	}
	return Plan{Changes: changes, Unchanged: len(changes) == 0}, nil
}
