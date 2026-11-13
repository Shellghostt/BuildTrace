package manifest

import "sort"

// sortArtifacts orders the artifacts by path.
//
// The order is part of the format: two manifests of the same build must be
// byte-identical, and the order the files were named on the command line
// is not a property of the build.
func sortArtifacts(artifacts []Artifact) {
	sort.SliceStable(artifacts, func(i, j int) bool {
		if artifacts[i].Path != artifacts[j].Path {
			return artifacts[i].Path < artifacts[j].Path
		}
		return artifacts[i].Name < artifacts[j].Name
	})
}
