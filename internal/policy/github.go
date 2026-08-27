// ABOUTME: Compiled default-deny allowlist for GitHub Enterprise Server (/api/v3) calls.
// ABOUTME: Archive downloads are pinned to the codeload origin by rule, never by following a host.
package policy

// repository matches an owner/name pair as one capture group, so repository
// scoping compares the same "owner/name" string an operator configures.
const repository = `([^/]+/[^/]+)`

// gitHubRules is the compiled GitHub Enterprise surface Zenfra needs. Everything
// absent here is denied, including every write beyond PR comments, check runs and
// commit statuses. GitHub.com is not a target: it needs no connector.
//
// GitHub answers the tarball endpoint with a redirect to a download origin. That
// origin is pinned by --codeload-endpoint and named here by rule; the connector
// takes only the path from the redirect, so a rewritten Location cannot move the
// download (or the credential) to a host the operator never configured.
func gitHubRules() []Rule {
	return compile([]ruleSpec{
		{id: "github.user.current", purpose: "Get Current User", method: "GET",
			pattern: `^/api/v3/user$`},
		// ponytail: the repository list exposes names outside --allowed-projects,
		// which repo discovery needs. Response filtering, if ever wanted, belongs in
		// the discovery service, not the path allowlist.
		{id: "github.repos.list", purpose: "List Repositories", method: "GET",
			pattern: `^/api/v3/user/repos$`},
		{id: "github.repo.get", purpose: "Get Repository", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `$`},
		{id: "github.repo.contents", purpose: "Get Repository Contents", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/contents(?:/.+)?$`},
		{id: "github.branches.list", purpose: "List Branches", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/branches$`},
		{id: "github.branch.get", purpose: "Get Branch", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/branches/[^/]+$`},
		{id: "github.commits.list", purpose: "List Commits", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/commits$`},
		{id: "github.commit.get", purpose: "Get Commit", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/commits/[^/]+$`},
		{id: "github.compare", purpose: "Compare Refs", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/compare/[^/]+$`},
		{id: "github.repository.tarball", purpose: "Download Repository Archive", method: "GET",
			pattern:     `^/api/v3/repos/` + repository + `/tarball(?:/[^/]*)?$`,
			redirectsTo: OriginCodeload},
		{id: "github.pull_requests.list", purpose: "List Pull Requests", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/pulls$`},
		{id: "github.pull_request.get", purpose: "Get Pull Request", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/pulls/[0-9]+$`},
		{id: "github.pull_request.files", purpose: "Get Pull Request Files", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/pulls/[0-9]+/files$`},
		{id: "github.pull_request.comments.list", purpose: "List Pull Request Comments", method: "GET",
			pattern: `^/api/v3/repos/` + repository + `/issues/[0-9]+/comments$`},
		{id: "github.pull_request.comment.create", purpose: "Comment on Pull Request", method: "POST",
			pattern: `^/api/v3/repos/` + repository + `/issues/[0-9]+/comments$`},
		{id: "github.pull_request.comment.update", purpose: "Update Pull Request Comment", method: "PATCH",
			pattern: `^/api/v3/repos/` + repository + `/issues/comments/[0-9]+$`},
		{id: "github.check_run.create", purpose: "Create Check Run", method: "POST",
			pattern: `^/api/v3/repos/` + repository + `/check-runs$`},
		{id: "github.check_run.update", purpose: "Update Check Run", method: "PATCH",
			pattern: `^/api/v3/repos/` + repository + `/check-runs/[0-9]+$`},
		{id: "github.commit.status.create", purpose: "Set Commit Status", method: "POST",
			pattern: `^/api/v3/repos/` + repository + `/statuses/[^/]+$`},

		// The codeload lane. Both shapes are archive downloads and nothing else:
		// GitHub Enterprise serves them under /_codeload on the API host, and a
		// cluster with a dedicated download host serves them at its root.
		{id: "github.codeload.archive", purpose: "Download Repository Archive", method: "GET",
			pattern: `^/_codeload/` + repository + `/(?:legacy\.)?(?:tar\.gz|zip)/.+$`,
			origin:  OriginCodeload},
		{id: "github.codeload.archive.host", purpose: "Download Repository Archive", method: "GET",
			pattern: `^/` + repository + `/(?:legacy\.)?(?:tar\.gz|zip)/.+$`,
			origin:  OriginCodeload},
	})
}
