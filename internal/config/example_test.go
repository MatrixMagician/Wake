package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"
)

// exampleConfigPath is deploy/wake.example.toml relative to this package
// directory (internal/config), which is two levels below the repo root.
const exampleConfigPath = "../../deploy/wake.example.toml"

// TestExampleConfigParsesAndValidates proves deploy/wake.example.toml is
// itself a valid Wake configuration: it decodes with no unknown keys and
// passes Validate.
func TestExampleConfigParsesAndValidates(t *testing.T) {
	cfg, err := Load(exampleConfigPath)
	if err != nil {
		t.Fatalf("Load(%s): %v", exampleConfigPath, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on example config: %v", err)
	}
}

// TestExampleConfigDocumentsEveryKnob is the anti-rot mechanism the task
// description asks for: it fails when a field is added to Config (at any
// nesting depth, including the element type of a repeatable table) without
// a corresponding "key = value" mention — commented out or not — in
// deploy/wake.example.toml. It is a leaf-name check, not a full-path check,
// because TOML table keys are written unqualified inside their table, but
// it is precise enough to catch a genuinely new, undocumented knob.
func TestExampleConfigDocumentsEveryKnob(t *testing.T) {
	leaves := collectTOMLLeaves(reflect.TypeOf(Config{}))
	if len(leaves) == 0 {
		t.Fatal("collectTOMLLeaves found nothing; the walker is broken")
	}

	raw, err := os.ReadFile(filepath.Clean(exampleConfigPath))
	if err != nil {
		t.Fatalf("reading %s: %v", exampleConfigPath, err)
	}
	text := string(raw)

	for _, leaf := range leaves {
		// A leaf is documented if its name appears as a whole word anywhere
		// in the file: as "name = value" for scalar/slice fields, or as
		// "[name]" / "[[name]]" / "[parent.name]" for table and
		// map-typed fields such as [classes]. Word boundaries stop
		// "cooldown" from being satisfied by, say, "cooldowns".
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(leaf) + `\b`)
		if !re.MatchString(text) {
			t.Errorf("config field %q is not documented anywhere in %s; "+
				"add it there (commented if it belongs to a repeatable table)",
				leaf, exampleConfigPath)
		}
	}
}

// collectTOMLLeaves walks a config struct type via its `toml` tags and
// returns every leaf field name (structs and slices-of-structs are
// recursed into; maps, slices-of-scalars, durations and other scalars are
// leaves). It intentionally returns only the final path component: see
// TestExampleConfigDocumentsEveryKnob's doc comment for why.
func collectTOMLLeaves(t reflect.Type) []string {
	var out []string
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t == reflect.TypeOf(time.Duration(0)) {
			return // handled as a leaf by the caller before recursing in
		}
		// Only structs have TOML keys to collect; everything else is a leaf.
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("toml")
			if tag == "" || tag == "-" {
				continue
			}
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft == reflect.TypeOf(time.Duration(0)) {
				out = append(out, tag)
				continue
			}
			switch ft.Kind() {
			case reflect.Struct:
				walk(ft)
			case reflect.Slice:
				elem := ft.Elem()
				if elem.Kind() == reflect.Struct {
					walk(elem)
				} else {
					out = append(out, tag)
				}
			default:
				out = append(out, tag)
			}
		}
	}
	walk(t)
	return out
}
