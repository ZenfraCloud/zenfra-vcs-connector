// ABOUTME: Compiled default-deny allowlist for Bitbucket Data Center (/rest/api/1.0) calls.
// ABOUTME: Repository identity spans two path segments, so scoping joins PROJECT and repo slug.
package policy

// bitbucketRepo matches the project key and repository slug that together name a
// Bitbucket repository. Both are capture groups; the engine joins them, so
// --allowed-projects is configured as "PROJECT/repo" like every other vendor.
const bitbucketRepo = `/rest/api/1\.0/projects/([^/]+)/repos/([^/]+)`

// bitbucketRules is the compiled Bitbucket Data Center surface Zenfra needs.
// Everything absent here is denied, including every write beyond PR comments and
// build statuses.
//
// Bitbucket serves repository archives from the API host with no redirect, so
// unlike GitHub there is no second pinned origin: every rule is primary-only and
// none may follow a redirect.
//
// Build statuses use the repository-scoped /commits/{id}/builds resource (Data
// Center 7.4+) rather than the older global /rest/build-status/1.0/commits/{id}:
// the old path carries no project, so --allowed-projects could not scope it and
// a connector would be able to mark any commit on the instance.
func bitbucketRules() []Rule {
	return compile([]ruleSpec{
		// ponytail: /users requires authentication, and Data Center names the
		// authenticated user in the X-AUSERNAME response header — that pair is
		// how verify observes an identity without a "current user" endpoint.
		{id: "bitbucket.user.current", purpose: "Get Current User", method: "GET",
			pattern: `^/rest/api/1\.0/users$`},
		// ponytail: the repository list exposes names outside --allowed-projects,
		// which repo discovery needs. Response filtering, if ever wanted, belongs
		// in the discovery service, not the path allowlist.
		{id: "bitbucket.repos.list", purpose: "List Repositories", method: "GET",
			pattern: `^/rest/api/1\.0/repos$`},
		{id: "bitbucket.repo.get", purpose: "Get Repository", method: "GET",
			pattern: `^` + bitbucketRepo + `$`},
		{id: "bitbucket.repo.browse", purpose: "Browse Repository", method: "GET",
			pattern: `^` + bitbucketRepo + `/browse(?:/.+)?$`},
		{id: "bitbucket.repo.raw", purpose: "Get Raw File", method: "GET",
			pattern: `^` + bitbucketRepo + `/raw/.+$`},
		{id: "bitbucket.branches.list", purpose: "List Branches", method: "GET",
			pattern: `^` + bitbucketRepo + `/branches$`},
		{id: "bitbucket.branches.default", purpose: "Get Default Branch", method: "GET",
			pattern: `^` + bitbucketRepo + `/branches/default$`},
		{id: "bitbucket.commits.list", purpose: "List Commits", method: "GET",
			pattern: `^` + bitbucketRepo + `/commits$`},
		{id: "bitbucket.commit.get", purpose: "Get Commit", method: "GET",
			pattern: `^` + bitbucketRepo + `/commits/[^/]+$`},
		{id: "bitbucket.commit.diff", purpose: "Get Commit Diff", method: "GET",
			pattern: `^` + bitbucketRepo + `/commits/[^/]+/diff(?:/.+)?$`},
		{id: "bitbucket.commit.changes", purpose: "List Commit Changes", method: "GET",
			pattern: `^` + bitbucketRepo + `/commits/[^/]+/changes$`},
		{id: "bitbucket.repository.archive", purpose: "Download Repository Archive", method: "GET",
			pattern: `^` + bitbucketRepo + `/archive$`},
		{id: "bitbucket.pull_requests.list", purpose: "List Pull Requests", method: "GET",
			pattern: `^` + bitbucketRepo + `/pull-requests$`},
		{id: "bitbucket.pull_request.get", purpose: "Get Pull Request", method: "GET",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+$`},
		{id: "bitbucket.pull_request.changes", purpose: "Get Pull Request Changes", method: "GET",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+/changes$`},
		{id: "bitbucket.pull_request.diff", purpose: "Get Pull Request Diff", method: "GET",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+/diff$`},
		{id: "bitbucket.pull_request.comments.list", purpose: "List Pull Request Comments", method: "GET",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+/comments$`},
		{id: "bitbucket.pull_request.comment.create", purpose: "Comment on Pull Request", method: "POST",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+/comments$`},
		{id: "bitbucket.pull_request.comment.update", purpose: "Update Pull Request Comment", method: "PUT",
			pattern: `^` + bitbucketRepo + `/pull-requests/[0-9]+/comments/[0-9]+$`},
		{id: "bitbucket.build_statuses.list", purpose: "List Build Statuses", method: "GET",
			pattern: `^` + bitbucketRepo + `/commits/[^/]+/builds$`},
		{id: "bitbucket.build_status.set", purpose: "Set Build Status", method: "POST",
			pattern: `^` + bitbucketRepo + `/commits/[^/]+/builds$`},
	})
}
