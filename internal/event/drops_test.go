package event

import "testing"

// Drop accounting is load-bearing: a flight recorder that loses events
// silently is worse than none (CLAUDE.md, "Nothing disappears silently"). This
// file pins the behaviours the rest of the daemon relies on, including the two
// deliberate asymmetries that a reader would otherwise be tempted to "tidy".

func TestDropsAddAndGet(t *testing.T) {
	t.Parallel()
	var d Drops
	d.Add(BoundaryRing, ClassExec, 3)
	d.Add(BoundaryRing, ClassExec, 4)

	if got := d.Get(BoundaryRing, ClassExec); got != 7 {
		t.Errorf("Get after two Adds = %d, want 7", got)
	}
	if got := d.Get(BoundaryKernel, ClassExec); got != 0 {
		t.Errorf("an untouched counter reads %d, want 0", got)
	}
	if got := d.Total(); got != 7 {
		t.Errorf("Total = %d, want 7", got)
	}
}

func TestDropsSetOverwrites(t *testing.T) {
	t.Parallel()
	var d Drops
	// Kernel-side counters are absolute totals read from a BPF map, so they
	// are stored rather than accumulated.
	d.Set(BoundaryKernel, ClassOpen, 100)
	d.Set(BoundaryKernel, ClassOpen, 42)
	if got := d.Get(BoundaryKernel, ClassOpen); got != 42 {
		t.Errorf("Get after Set = %d, want 42 (Set must overwrite, not add)", got)
	}
}

func TestUnknownClassFoldsIntoGeneric(t *testing.T) {
	t.Parallel()
	var d Drops
	d.Add(BoundaryDecode, Class("telepathy"), 5)

	if got := d.Get(BoundaryDecode, ClassGeneric); got != 5 {
		t.Errorf("generic counter = %d, want 5: an unknown class must still be "+
			"counted somewhere, because losing the record of a loss is the one "+
			"unacceptable failure here", got)
	}
	if got := d.Total(); got != 5 {
		t.Errorf("Total = %d, want 5", got)
	}
}

func TestGetOfUnknownClassDoesNotFold(t *testing.T) {
	t.Parallel()
	var d Drops
	d.Add(BoundaryDecode, ClassGeneric, 9)

	// Add folds an unknown class into generic; Get deliberately does not, or a
	// reader asking about a class that does not exist would be handed some
	// other class's count and believe it.
	if got := d.Get(BoundaryDecode, Class("telepathy")); got != 0 {
		t.Errorf("Get(unknown class) = %d, want 0", got)
	}
}

func TestUnknownBoundaryIsIgnored(t *testing.T) {
	t.Parallel()
	var d Drops
	d.Add(Boundary("telepathy"), ClassExec, 5)
	// There is no "generic boundary" to fold into, so the update has nowhere
	// to go. It must not land on some arbitrary real boundary.
	if got := d.Total(); got != 0 {
		t.Errorf("Total = %d, want 0: an unknown boundary must not be counted "+
			"against a real one", got)
	}
}

func TestReportCoversEveryBoundaryAndClass(t *testing.T) {
	t.Parallel()
	var d Drops
	d.Add(BoundaryWatch, ClassConnect, 2)
	r := d.Report()

	// Zero counters are included deliberately: a reader must be able to tell
	// "nothing was lost here" apart from "this boundary is not reported".
	if len(r) != len(Boundaries) {
		t.Fatalf("report covers %d boundaries, want %d", len(r), len(Boundaries))
	}
	for _, b := range Boundaries {
		classes, ok := r[string(b)]
		if !ok {
			t.Fatalf("boundary %q missing from the report", b)
		}
		if len(classes) != len(Classes) {
			t.Errorf("boundary %q covers %d classes, want %d", b, len(classes), len(Classes))
		}
		for _, c := range Classes {
			if _, ok := classes[string(c)]; !ok {
				t.Errorf("class %q missing from boundary %q", c, b)
			}
		}
	}
	if got := r[string(BoundaryWatch)][string(ClassConnect)]; got != 2 {
		t.Errorf("reported count = %d, want 2", got)
	}
}

// TestCounterGridCoversEveryClass is the regression guard for the constants
// this grid used to carry. Adding a class to Classes now resizes the grid at
// compile time; this fails loudly if that ever stops being true.
func TestCounterGridCoversEveryClass(t *testing.T) {
	t.Parallel()
	var d Drops
	for _, b := range Boundaries {
		for _, c := range Classes {
			d.Add(b, c, 1)
		}
	}
	want := uint64(len(Boundaries) * len(Classes))
	if got := d.Total(); got != want {
		t.Errorf("Total = %d, want %d: every boundary/class pair must have its "+
			"own counter, with no pair aliasing another", got, want)
	}
}
