package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/loader"
	"github.com/MatrixMagician/wake/internal/trigger"
)

// This file is the translation layer between the configuration vocabulary and
// the kernel-facing and trigger-facing vocabularies. It exists so that neither
// internal/loader nor internal/trigger has to import internal/config, which is
// what keeps a renamed TOML key from rippling into the BPF plumbing.

func loaderOptions(cfg *config.Config) (loader.Options, error) {
	opts := loader.Options{
		RingBufBytes: defaultRingBufBytes,
		Classes:      enabledClasses(cfg),
		CommAllow:    cfg.Scope.CommAllow,
		CommDeny:     cfg.Scope.CommDeny,
		PathPrefixes: cfg.Filters.PathPrefixes,
		SelfPID:      int32(os.Getpid()), //nolint:gosec
	}

	if cfg.Scope.CgroupSubtree != "" {
		opts.CgroupPaths = []string{cfg.Scope.CgroupSubtree}
	}

	ports, err := expandPorts(cfg.Filters.Ports)
	if err != nil {
		return opts, err
	}
	opts.Ports = ports

	if cfg.Triggers.Signal.Enabled {
		for _, name := range cfg.Triggers.Signal.Signals {
			s, err := config.ParseSignalName(name)
			if err != nil {
				return opts, err
			}
			opts.Signals = append(opts.Signals, int32(s))
		}
	}

	return opts, nil
}

// filterCIDRs parses the configured destination-network filter for the
// recorder. It is not part of loaderOptions because this filter is applied in
// userspace, after decode and before the ring, rather than in kernel — see
// docs/decisions/0002-cidr-filtering-in-userspace.md. Prefixes are masked so a
// value written with host bits set ("10.0.0.1/8") behaves as the network the
// operator meant.
func filterCIDRs(cfg *config.Config) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range cfg.Filters.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("filter cidr %q: %w", c, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// defaultRingBufBytes sizes the kernel ring buffer. 4 MiB absorbs a burst of
// several thousand events while userspace is scheduled out, which is the
// failure mode that produces kernel-side drops.
const defaultRingBufBytes = 4 << 20

// expandPorts turns the configuration's port specifications, which may be
// single ports or inclusive ranges, into the flat list the kernel map wants.
func expandPorts(specs []string) ([]uint16, error) {
	var out []uint16
	for _, spec := range specs {
		lo, hi, isRange := strings.Cut(spec, "-")
		low, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("filter port %q: %w", spec, err)
		}
		high := low
		if isRange {
			high, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("filter port range %q: %w", spec, err)
			}
		}
		if high < low {
			return nil, fmt.Errorf("filter port range %q is inverted", spec)
		}
		// A range wider than the map can hold would silently truncate, which
		// is exactly the kind of quiet filtering failure this project refuses.
		if high-low > maxPortRange {
			return nil, fmt.Errorf("filter port range %q spans %d ports; "+
				"the in-kernel map holds %d, so this would filter silently and wrongly",
				spec, high-low+1, maxPortRange)
		}
		for p := low; p <= high; p++ {
			out = append(out, uint16(p)) //nolint:gosec // bounded by ParseUint's bitSize
		}
	}
	return out, nil
}

// maxPortRange mirrors the port_filter map's max_entries in bpf/wake_maps.h.
const maxPortRange = 1024

// triggerRules turns the configuration's five trigger sections into the
// engine's flat rule list.
func triggerRules(cfg *config.Config) ([]trigger.Rule, error) {
	var rules []trigger.Rule

	for _, w := range cfg.Triggers.WatchedProcess {
		pred, err := config.ParseExitCodePredicate(w.ExitCode)
		if err != nil {
			return nil, fmt.Errorf("trigger %q: %w", w.Name, err)
		}
		rule := trigger.Rule{
			Name:     w.Name,
			Type:     trigger.TypeProcess,
			Cooldown: w.Cooldown,
			Comm:     w.CommGlob,
			Cgroup:   w.CgroupGlob,
			Unit:     w.UnitGlob,
		}
		// An unset exit_code leaves Exit nil, which the engine reads as its
		// documented default: any abnormal exit. That is deliberately not the
		// same as an explicit "any", which per the config grammar matches every
		// exit, clean ones included.
		if strings.TrimSpace(w.ExitCode) != "" {
			rule.Exit = pred.Match
		}
		rules = append(rules, rule)
	}

	if cfg.Triggers.OOM.Enabled {
		rules = append(rules, trigger.Rule{
			Name: "oom", Type: trigger.TypeOOM, Cooldown: cfg.Triggers.OOM.Cooldown,
		})
	}

	if cfg.Triggers.Signal.Enabled {
		r := trigger.Rule{
			Name: "signal", Type: trigger.TypeSignal, Cooldown: cfg.Triggers.Signal.Cooldown,
		}
		for _, name := range cfg.Triggers.Signal.Signals {
			s, err := config.ParseSignalName(name)
			if err != nil {
				return nil, err
			}
			r.Signals = append(r.Signals, int32(s))
		}
		rules = append(rules, r)
	}

	if cfg.Triggers.UnitFailed.Enabled {
		if len(cfg.Triggers.UnitFailed.Units) == 0 {
			rules = append(rules, trigger.Rule{
				Name: "unit-failed", Type: trigger.TypeUnit,
				Cooldown: cfg.Triggers.UnitFailed.Cooldown,
			})
		}
		for i, u := range cfg.Triggers.UnitFailed.Units {
			rules = append(rules, trigger.Rule{
				Name:     fmt.Sprintf("unit-failed-%d", i),
				Type:     trigger.TypeUnit,
				Unit:     u,
				Cooldown: cfg.Triggers.UnitFailed.Cooldown,
			})
		}
	}

	return rules, nil
}
