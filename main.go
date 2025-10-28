package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"
	"github.com/urfave/cli/v3"
	"golang.org/x/oauth2"
)

var csvHeader = []string{
	"repository",
	"branch",
	"sha",
	"date",
	"author",
	"author_login",
	"author_email",
	"committer",
	"committer_login",
	"committer_email",
	"co_authors",
	"message",
}

func main() {
	cmd := &cli.Command{
		Name:  "changelog",
		Usage: "Export commit activity for an organisation in CSV format",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "org",
				Usage:    "GitHub organisation to inspect",
				Required: true,
			},
			&cli.IntFlag{
				Name:     "fy",
				Usage:    "Australian fiscal year identifier (e.g. 25 for FY24-25)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "main-branch",
				Usage: "Reference branch to compare against",
				Value: "main",
			},
			&cli.StringSliceFlag{
				Name:  "ignore-user",
				Usage: "GitHub username to ignore (repeatable)",
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	org := strings.TrimSpace(cmd.String("org"))
	if org == "" {
		return errors.New("org flag is required")
	}

	fy := cmd.Int("fy")
	location, err := time.LoadLocation("Australia/Sydney")
	if err != nil {
		return fmt.Errorf("load location: %w", err)
	}

	start, end, err := fiscalYearBounds(fy, location)
	if err != nil {
		return err
	}

	log.Printf(
		"Analysing org %s for FY%d window %s to %s",
		org,
		fy,
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)

	baseBranch := strings.TrimSpace(cmd.String("main-branch"))
	ignoredUsers := make(map[string]struct{})
	for _, user := range cmd.StringSlice("ignore-user") {
		if user = strings.ToLower(strings.TrimSpace(user)); user != "" {
			ignoredUsers[user] = struct{}{}
		}
	}

	seenCommits := make(map[string]struct{})

	token, err := ghToken(ctx)
	if err != nil {
		return err
	}

	client := newGitHubClient(ctx, token)

	writer := csv.NewWriter(os.Stdout)
	if err := writer.Write(csvHeader); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	repoOpts := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		page := repoOpts.ListOptions.Page

		if err := ctx.Err(); err != nil {
			return err
		}

		repos, resp, err := client.Repositories.ListByOrg(ctx, org, repoOpts)
		if err != nil {
			return fmt.Errorf("list repositories: %w", err)
		}

		log.Printf("Fetched %d repositories on page %d", len(repos), page)

		for _, repo := range repos {
			if repo == nil {
				continue
			}

			if err := exportRepository(ctx, client, org, repo, baseBranch, start, end, location, ignoredUsers, seenCommits, writer); err != nil {
				return err
			}
		}

		if resp.NextPage == 0 {
			break
		}
		repoOpts.ListOptions.Page = resp.NextPage
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}

	log.Printf("Export complete")

	return nil
}

func exportRepository(
	ctx context.Context,
	client *github.Client,
	org string,
	repo *github.Repository,
	requestedBaseBranch string,
	start time.Time,
	end time.Time,
	location *time.Location,
	ignoredUsers map[string]struct{},
	seenCommits map[string]struct{},
	writer *csv.Writer,
) error {
	repoName := repo.GetName()
	baseBranch := requestedBaseBranch
	if baseBranch == "" {
		baseBranch = repo.GetDefaultBranch()
	}

	if baseBranch == "" {
		fmt.Fprintf(os.Stderr, "warning: repo %s has no identifiable base branch; skipping\n", repoName)
		return nil
	}

	if _, _, err := client.Repositories.GetBranch(ctx, org, repoName, baseBranch, 0); err != nil {
		defaultBranch := repo.GetDefaultBranch()
		if defaultBranch != "" && !strings.EqualFold(defaultBranch, baseBranch) {
			if _, _, derr := client.Repositories.GetBranch(ctx, org, repoName, defaultBranch, 0); derr == nil {
				fmt.Fprintf(
					os.Stderr,
					"info: repo %s does not have branch %s; using default branch %s\n",
					repoName,
					baseBranch,
					defaultBranch,
				)
				baseBranch = defaultBranch
			} else {
				fmt.Fprintf(os.Stderr, "warning: repo %s cannot access %s: %v\n", repoName, baseBranch, err)
				return nil
			}
		} else {
			fmt.Fprintf(os.Stderr, "warning: repo %s cannot access %s: %v\n", repoName, baseBranch, err)
			return nil
		}
	}

	log.Printf("Repository %s: using base branch %s", repoName, baseBranch)

	branchOpts := &github.BranchListOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		branches, resp, err := client.Repositories.ListBranches(ctx, org, repoName, branchOpts)
		if err != nil {
			return fmt.Errorf("list branches for %s: %w", repoName, err)
		}

		for _, branch := range branches {
			if branch == nil {
				continue
			}

			branchName := branch.GetName()
			include := branchName == baseBranch
			if !include {
				compare, _, err := client.Repositories.CompareCommits(ctx, org, repoName, baseBranch, branchName, nil)
				if err != nil {
					if !isNotFound(err) {
						fmt.Fprintf(os.Stderr, "warning: repo %s compare %s..%s: %v\n", repoName, baseBranch, branchName, err)
					}
					continue
				}
				if compare.GetAheadBy() == 0 {
					log.Printf("Repository %s: branch %s is already merged into %s", repoName, branchName, baseBranch)
					continue
				}
			}

			log.Printf("Repository %s: exporting branch %s", repoName, branchName)

			if err := exportBranchCommits(ctx, client, org, repoName, branchName, start, end, location, ignoredUsers, seenCommits, writer); err != nil {
				return err
			}

			writer.Flush()
			if err := writer.Error(); err != nil {
				return fmt.Errorf("flush csv after branch %s: %w", branchName, err)
			}
		}

		if resp.NextPage == 0 {
			break
		}
		branchOpts.ListOptions.Page = resp.NextPage
	}

	return nil
}

func exportBranchCommits(
	ctx context.Context,
	client *github.Client,
	org, repo, branch string,
	start, end time.Time,
	location *time.Location,
	ignoredUsers map[string]struct{},
	seenCommits map[string]struct{},
	writer *csv.Writer,
) error {
	commitOpts := &github.CommitsListOptions{
		SHA:   branch,
		Since: start,
		Until: end,
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		page := commitOpts.ListOptions.Page

		commits, resp, err := client.Repositories.ListCommits(ctx, org, repo, commitOpts)
		if err != nil {
			return fmt.Errorf("list commits for %s/%s (%s): %w", org, repo, branch, err)
		}

		log.Printf(
			"Repository %s: branch %s page %d returned %d commits",
			repo,
			branch,
			page,
			len(commits),
		)

		for _, commit := range commits {
			if commit == nil || commit.Commit == nil {
				continue
			}

			fullSHA := strings.TrimSpace(commit.GetSHA())
			if fullSHA == "" {
				continue
			}
			if _, exists := seenCommits[fullSHA]; exists {
				log.Printf(
					"Repository %s: branch %s skipping duplicate commit %s",
					repo,
					branch,
					shortSHA(fullSHA),
				)
				continue
			}

			entry, skip := buildCommitEntry(commit, repo, branch, start, end, location, ignoredUsers)
			if skip {
				continue
			}

			seenCommits[fullSHA] = struct{}{}

			if err := writer.Write(entry.toRecord()); err != nil {
				return fmt.Errorf("write commit row: %w", err)
			}
		}

		if resp.NextPage == 0 {
			break
		}
		commitOpts.ListOptions.Page = resp.NextPage
	}

	return nil
}

type commitEntry struct {
	Repository     string
	Branch         string
	SHA            string
	CommitDate     time.Time
	AuthorName     string
	AuthorLogin    string
	AuthorEmail    string
	CommitterName  string
	CommitterLogin string
	CommitterEmail string
	CoAuthors      []string
	Message        string
}

func (e *commitEntry) toRecord() []string {
	date := ""
	if !e.CommitDate.IsZero() {
		date = e.CommitDate.Format(time.RFC3339)
	}

	return []string{
		e.Repository,
		e.Branch,
		e.SHA,
		date,
		e.AuthorName,
		e.AuthorLogin,
		e.AuthorEmail,
		e.CommitterName,
		e.CommitterLogin,
		e.CommitterEmail,
		strings.Join(e.CoAuthors, "; "),
		e.Message,
	}
}

type identity struct {
	Name  string
	Email string
	Login string
	Type  string
}

func buildCommitEntry(
	repoCommit *github.RepositoryCommit,
	repoName,
	branchName string,
	start, end time.Time,
	location *time.Location,
	ignoredUsers map[string]struct{},
) (*commitEntry, bool) {
	entry := &commitEntry{
		Repository: repoName,
		Branch:     branchName,
		SHA:        shortSHA(repoCommit.GetSHA()),
		Message:    singleLineMessage(repoCommit.GetCommit().GetMessage()),
	}

	commitData := repoCommit.GetCommit()
	if commitData == nil {
		return nil, true
	}

	authorIdentity := extractIdentity(repoCommit.Author, commitData.Author)
	if hasIgnoredLogin(authorIdentity, ignoredUsers) || isFilteredIdentity(authorIdentity) {
		return nil, true
	}
	entry.AuthorName = authorIdentity.Name
	entry.AuthorLogin = authorIdentity.Login
	entry.AuthorEmail = authorIdentity.Email

	committerIdentity := extractIdentity(repoCommit.Committer, commitData.Committer)
	if hasIgnoredLogin(committerIdentity, ignoredUsers) {
		return nil, true
	}
	if isFilteredIdentity(committerIdentity) {
		committerIdentity = identity{}
	}
	entry.CommitterName = committerIdentity.Name
	entry.CommitterLogin = committerIdentity.Login
	entry.CommitterEmail = committerIdentity.Email

	entry.CoAuthors = filterCoAuthors(parseCoAuthors(commitData.GetMessage()), ignoredUsers)

	commitDate := commitData.GetAuthor().GetDate().Time
	if commitDate.IsZero() {
		commitDate = commitData.GetCommitter().GetDate().Time
	}
	if !commitDate.IsZero() {
		if location != nil {
			commitDate = commitDate.In(location)
		} else {
			commitDate = commitDate.UTC()
		}
	}

	// Safety check in case API ignores filtering parameters
	if (!start.IsZero() && commitDate.Before(start)) || (!end.IsZero() && commitDate.After(end)) {
		return nil, true
	}

	entry.CommitDate = commitDate

	return entry, false
}

func extractIdentity(user *github.User, commitAuthor *github.CommitAuthor) identity {
	var out identity

	if user != nil {
		out.Login = strings.ToLower(strings.TrimSpace(user.GetLogin()))
		out.Name = strings.TrimSpace(user.GetName())
		if out.Name == "" {
			out.Name = user.GetLogin()
		}
		out.Email = strings.TrimSpace(user.GetEmail())
		out.Type = strings.TrimSpace(user.GetType())
	}

	if commitAuthor != nil {
		if out.Name == "" {
			out.Name = strings.TrimSpace(commitAuthor.GetName())
		}
		if out.Email == "" {
			out.Email = strings.TrimSpace(commitAuthor.GetEmail())
		}
		if out.Login == "" {
			out.Login = strings.ToLower(strings.TrimSpace(commitAuthor.GetLogin()))
		}
	}

	if out.Login == "" {
		out.Login = loginFromEmail(out.Email)
	}

	if out.Name == "" {
		out.Name = out.Login
	}

	return out
}

func hasIgnoredLogin(id identity, ignoredUsers map[string]struct{}) bool {
	login := strings.ToLower(strings.TrimSpace(id.Login))
	if login != "" {
		_, ok := ignoredUsers[login]
		return ok
	}
	return false
}

func isFilteredIdentity(id identity) bool {
	login := strings.ToLower(strings.TrimSpace(id.Login))
	if login == "github" {
		return true
	}
	if isBotLogin(login) {
		return true
	}

	if strings.EqualFold(strings.TrimSpace(id.Type), "bot") {
		return true
	}

	name := strings.ToLower(strings.TrimSpace(id.Name))
	if name == "github" {
		return true
	}

	email := strings.ToLower(strings.TrimSpace(id.Email))
	if email == "noreply@github.com" || email == "github@github.com" {
		return true
	}

	return false
}

func filterCoAuthors(coAuthors []identity, ignoredUsers map[string]struct{}) []string {
	if len(coAuthors) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var filtered []string
	for _, id := range coAuthors {
		if hasIgnoredLogin(id, ignoredUsers) || isFilteredIdentity(id) {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(id.Email))
		if key == "" {
			key = id.Login
		}
		if key == "" {
			key = id.Name
		}
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		display := strings.TrimSpace(id.Name)
		if display == "" && id.Login != "" {
			display = id.Login
		}
		email := strings.TrimSpace(id.Email)
		if email != "" {
			filtered = append(filtered, fmt.Sprintf("%s <%s>", display, email))
		} else {
			filtered = append(filtered, display)
		}
	}

	return filtered
}

func parseCoAuthors(message string) []identity {
	lines := strings.Split(message, "\n")
	var result []identity
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		const prefix = "co-authored-by:"
		if !strings.HasPrefix(strings.ToLower(line), prefix) {
			continue
		}
		content := strings.TrimSpace(line[len(prefix):])
		if content == "" {
			continue
		}

		name := content
		email := ""
		if lt := strings.IndexRune(content, '<'); lt >= 0 {
			if gt := strings.IndexRune(content[lt:], '>'); gt >= 0 {
				email = strings.TrimSpace(content[lt+1 : lt+gt])
				name = strings.TrimSpace(content[:lt])
			}
		}

		result = append(result, identity{
			Name:  name,
			Email: email,
			Login: loginFromEmail(email),
		})
	}

	return result
}

func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func singleLineMessage(message string) string {
	message = strings.TrimSpace(message)
	if idx := strings.IndexByte(message, '\n'); idx >= 0 {
		message = message[:idx]
	}
	return strings.TrimSpace(message)
}

func loginFromEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}

	at := strings.IndexRune(email, '@')
	if at <= 0 {
		return ""
	}

	local := email[:at]
	if plus := strings.IndexRune(local, '+'); plus > 0 {
		local = local[:plus]
	}

	return strings.TrimSpace(local)
}

func isBotLogin(login string) bool {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return false
	}
	if strings.HasSuffix(login, "[bot]") {
		return true
	}
	if strings.HasSuffix(login, "-bot") {
		return true
	}
	if strings.HasSuffix(login, "bot") && len(login) > 3 {
		return true
	}
	if strings.Contains(login, "bot[") || strings.Contains(login, "bot/") || strings.Contains(login, "bot-") {
		return true
	}
	return false
}

func isNotFound(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	return false
}

func fiscalYearBounds(fy int, location *time.Location) (time.Time, time.Time, error) {
	if fy <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid fiscal year: %d", fy)
	}

	var year int
	switch {
	case fy >= 1000:
		year = fy
	case fy >= 100:
		year = 2000 + fy
	default:
		year = 2000 + fy
	}

	if location == nil {
		location = time.UTC
	}

	startYear := year - 1
	start := time.Date(startYear, time.July, 1, 0, 0, 0, 0, location)
	end := time.Date(year, time.June, 30, 23, 59, 59, int(time.Second-time.Nanosecond), location)

	return start, end, nil
}

func ghToken(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "gh", "auth", "token")
	command.Stderr = os.Stderr

	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("gh auth token: %w", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", errors.New("gh auth token returned empty token")
	}

	return token, nil
}

func newGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}
