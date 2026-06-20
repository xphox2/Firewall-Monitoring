// Command configcheck validates the firewall config change-detection normalizer
// against real backups. Point it at two config files (typically two backups of
// the same device taken at different times, or via different capture methods) and
// it reports whether they would raise a config-change alert and, if so, exactly
// which lines survived normalization.
//
// It is a developer/operator tool, not part of the running server: use it to
// confirm the normalizer neutralizes a newly-discovered volatile pattern before
// shipping, or to triage a false-positive config-change alert from the field.
//
//	go run ./cmd/configcheck --vendor fortigate old.conf new.conf
//	go run ./cmd/configcheck --vendor fortigate --max 50 a.conf b.conf
//	go run ./cmd/configcheck --objects --vendor fortigate old.conf new.conf
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"firewall-mon/internal/configdiff"
)

func main() {
	vendor := flag.String("vendor", "fortigate", "device vendor (fortigate, paloalto, cisco_asa, ...)")
	max := flag.Int("max", 40, "max residual diff lines to print per side (0 = all)")
	objects := flag.Bool("objects", false, "print the per-object semantic diff + risk classification instead of the line diff")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: configcheck [--vendor V] [--max N] <configA> <configB>\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	a, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read A:", err)
		os.Exit(1)
	}
	b, err := os.ReadFile(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read B:", err)
		os.Exit(1)
	}

	rep := configdiff.Analyze(*vendor, a, b)

	fmt.Printf("vendor:   %s\n", rep.Vendor)
	fmt.Printf("A:        %s  (%s, %d normalized lines)  %s\n", flag.Arg(0), rep.QualityA, rep.NormLinesA, rep.HashA)
	fmt.Printf("B:        %s  (%s, %d normalized lines)  %s\n", flag.Arg(1), rep.QualityB, rep.NormLinesB, rep.HashB)
	fmt.Println()

	if rep.Match {
		fmt.Println("RESULT:   MATCH — no config-change alert would fire.")
	} else {
		fmt.Printf("RESULT:   DIFFER — a config-change alert would fire (%d only-in-A, %d only-in-B).\n",
			len(rep.OnlyInA), len(rep.OnlyInB))
	}

	if rep.CaptureModeMismatch {
		fmt.Println()
		fmt.Println("WARN:     capture-mode mismatch")
		fmt.Println("          " + rep.CaptureModeReason)
	}

	if *objects {
		printObjects(rep)
	} else {
		printSide("only in A (removed)", rep.OnlyInA, *max)
		printSide("only in B (added)", rep.OnlyInB, *max)
	}

	if !rep.Match {
		os.Exit(1)
	}
}

// printObjects renders the semantic per-object diff and its risk classification.
func printObjects(rep configdiff.Report) {
	if len(rep.ObjectChanges) == 0 {
		fmt.Println("\n(no per-object diff — vendor has no object parser, or no object-level changes)")
		return
	}
	s := rep.Summary
	fmt.Printf("\nOBJECTS:  %d added, %d removed, %d modified  (max severity: %s)\n",
		s.Added, s.Removed, s.Modified, s.MaxSeverity)
	if s.Impact != "" {
		fmt.Printf("IMPACT:   %s\n", s.Impact)
	}
	for _, ch := range rep.ObjectChanges {
		fmt.Printf("\n  [%s] %-8s %s  (%s/%s)\n",
			strings.ToUpper(ch.Op), ch.Risk.Severity, ch.Path, ch.Risk.Category, ch.Risk.Summary)
		for _, d := range ch.Attrs {
			switch {
			case d.Old == "":
				fmt.Printf("      + %s = %s\n", d.Key, d.New)
			case d.New == "":
				fmt.Printf("      - %s = %s\n", d.Key, d.Old)
			default:
				fmt.Printf("      ~ %s : %s -> %s\n", d.Key, d.Old, d.New)
			}
		}
	}
}

func printSide(title string, lines []string, max int) {
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	fmt.Printf("\n%s (%d):\n", title, len(lines))
	for i, ln := range lines {
		if max > 0 && i >= max {
			fmt.Printf("  ... %d more (raise --max to see all)\n", len(lines)-max)
			break
		}
		fmt.Printf("  %s\n", ln)
	}
}
