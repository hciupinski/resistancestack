package ci

const (
	osvScannerWorkflowRef = "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.3.0"
	trivyActionRef        = "aquasecurity/trivy-action@v0.33.1"
)

type NodeProject struct {
	Path      string
	Package   string
	Framework string
}

type TechProfile struct {
	NodeProjects      []NodeProject
	DotnetProjects    []string
	Dockerfiles       []string
	ComposeFiles      []string
	ExistingWorkflows []string
}

type WorkflowFile struct {
	Name    string
	Path    string
	Content string
}

type ValidationResult struct {
	Missing  []string
	Outdated []string
}
