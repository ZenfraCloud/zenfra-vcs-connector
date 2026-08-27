// ABOUTME: Compiled default-deny allowlist for Azure DevOps Server (/_apis) calls.
// ABOUTME: Paths are collection-relative; project and repository together name the scope.
package policy

// azureDevOpsRepo matches the project and repository that together name an Azure
// DevOps repository. Both are capture groups; the engine joins them, so
// --allowed-projects is configured as "Project/repo" like every other vendor.
//
// The pattern is collection-relative: an Azure DevOps Server URL is
// {server}/{collection}/{project}/_apis/..., and the collection lives in the
// operator's --endpoint, so it never appears here and cannot be swapped by
// anything on the wire.
const azureDevOpsRepo = `/([^/]+)/_apis/git/repositories/([^/]+)`

// azureDevOpsAnchor starts every Azure DevOps pattern. Azure DevOps routes are
// case-insensitive (/pullrequests and /pullRequests are the same resource), so a
// case-sensitive allowlist would deny paths the upstream would happily serve
// while denying nothing an attacker could not simply re-case.
const azureDevOpsAnchor = `^(?i)`

// azureDevOpsRules is the compiled Azure DevOps Server surface Zenfra needs.
// Everything absent here is denied, including every write beyond pull-request
// comments and commit statuses.
//
// Azure DevOps serves repository archives from the collection host itself (the
// items resource with $format=zip), so there is no second pinned origin and no
// rule may follow a redirect.
func azureDevOpsRules() []Rule {
	return compile([]ruleSpec{
		// ponytail: connectionData is the only identity resource Azure DevOps
		// Server exposes without a project; a 200 proves the credential and names
		// the authenticated user.
		{id: "azure_devops.connection_data", purpose: "Get Current User", method: "GET",
			pattern: azureDevOpsAnchor + `/_apis/connectionData$`},
		// ponytail: the collection-wide repository list exposes names outside
		// --allowed-projects, which repo discovery needs. Response filtering, if
		// ever wanted, belongs in the discovery service, not the path allowlist.
		{id: "azure_devops.repos.list", purpose: "List Repositories", method: "GET",
			pattern: azureDevOpsAnchor + `/_apis/git/repositories$`},
		{id: "azure_devops.repo.get", purpose: "Get Repository", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `$`},
		// One resource serves directory listings, raw file content and the
		// repository archive; the $format query parameter picks which.
		{id: "azure_devops.repository.items", purpose: "Read Repository Items", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/items$`},
		{id: "azure_devops.refs.list", purpose: "List Branches", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/refs$`},
		{id: "azure_devops.commits.list", purpose: "List Commits", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/commits$`},
		{id: "azure_devops.commit.get", purpose: "Get Commit", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/commits/[^/]+$`},
		{id: "azure_devops.commit.changes", purpose: "List Commit Changes", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/commits/[^/]+/changes$`},
		{id: "azure_devops.commit.statuses.list", purpose: "List Commit Statuses", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/commits/[^/]+/statuses$`},
		{id: "azure_devops.commit.status.set", purpose: "Set Commit Status", method: "POST",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/commits/[^/]+/statuses$`},
		{id: "azure_devops.pull_requests.list", purpose: "List Pull Requests", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/pullrequests$`},
		{id: "azure_devops.pull_request.get", purpose: "Get Pull Request", method: "GET",
			pattern: azureDevOpsAnchor + azureDevOpsRepo + `/pullrequests/[0-9]+$`},
		{id: "azure_devops.pull_request.threads.list", purpose: "List Pull Request Comments",
			method: "GET", pattern: azureDevOpsAnchor + azureDevOpsRepo + `/pullrequests/[0-9]+/threads$`},
		{id: "azure_devops.pull_request.thread.create", purpose: "Comment on Pull Request",
			method: "POST", pattern: azureDevOpsAnchor + azureDevOpsRepo + `/pullrequests/[0-9]+/threads$`},
		{id: "azure_devops.pull_request.comment.update", purpose: "Update Pull Request Comment",
			method: "PATCH", pattern: azureDevOpsAnchor + azureDevOpsRepo +
				`/pullrequests/[0-9]+/threads/[0-9]+/comments/[0-9]+$`},
	})
}
