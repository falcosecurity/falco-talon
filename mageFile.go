//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func Lint() error {
	if err := sh.RunV("golangci-lint", "--version"); err != nil {
		return err
	}
	if err := sh.RunV("golangci-lint", "run", "--timeout", "3m"); err != nil {
		return err
	}
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	return nil
}

func FixLint() error {
	if err := sh.RunV("golangci-lint", "run", "--fix"); err != nil {
		return err
	}
	return nil
}

func Test() error {
	return sh.RunV("go", "test", "./...", "-race")
}

func Run() error {
	return sh.RunV("go", "run", "./...", "server", "-c", "config.yaml", "-r", "rules.yaml")
}

func BuildLocal() error {
	ldFlags := generateLDFlags()

	fmt.Println(ldFlags)
	return sh.RunV("go", "build", "-trimpath", "-ldflags", ldFlags, "-o", "falco-talon", ".")
}

// BuildImages build images locally and not push
func BuildLocaleImages() error {
	exportLDFlags()
	os.Setenv("KO_DOCKER_REPO", "ko.local/falco-talon")

	return sh.RunV("ko", "build", "--bare", "--sbom=none", "--tags", getVersion(), "--tags", getCommit(), "--tags", "latest",
		"github.com/Issif/falco-talon")
}

func BuildImages() error {
	exportLDFlags()
	os.Setenv("KO_DOCKER_REPO", "issif/falco-talon")

	return sh.RunV("ko", "build", "--bare", "--sbom=none", "--tags", getVersion(), "--tags", getCommit(), "--tags", "latest",
		"github.com/Issif/falco-talon")
}

func PushImages() error {
	mg.Deps(BuildImages)
	os.Setenv("KO_DOCKER_REPO", "issif/falco-talon")

	return sh.RunV("ko", "build", "--bare", "--sbom=none", "--tags", getVersion(), "--tags", getCommit(), "--tags", "latest",
		"github.com/Issif/falco-talon")
}

func Build() error {
	exportLDFlags()
	return sh.RunV("goreleaser", "release", "--clean", "--snapshot", "--skip-sbom", "--skip-publish")
}

func Release() error {
	mg.Deps(Test)

	exportLDFlags()
	return sh.RunV("goreleaser", "release", "--clean", "--skip-sign", "--skip-sbom")
}

func Clean() {
	files := []string{"falco-talon", "dist"}

	for _, file := range files {
		sh.Rm(file)
	}
}

// exportLDFlags export as env vars the flags for go build
func exportLDFlags() {
	os.Setenv("LDFLAGS", generateLDFlags())
}

// getVersion gets a description of the commit, e.g. v0.30.1 (latest) or v0.30.1-32-gfe72ff73 (canary)
func getVersion() string {
	version, _ := sh.Output("git", "describe", "--tags", "--match=v*")
	if version != "" {
		return version
	}

	gitBranch, _ := sh.Output("git", "branch", "--show-current")

	// repo without any tags in it
	return gitBranch
}

// getCommit gets the hash of the current commit
func getCommit() string {
	commit, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return commit
}

// getGitState gets the state of the git repository
func getGitState() string {
	_, err := sh.Output("git", "diff", "--quiet")
	if err != nil {
		return "dirty"
	}

	return "clean"
}

// getBuildDateTime gets the build date and time
func getBuildDateTime() string {
	result, _ := sh.Output("git", "log", "-1", "--pretty=%ct")
	if result != "" {
		sourceDateEpoch := fmt.Sprintf("@%s", result)
		date, _ := sh.Output("date", "-u", "-d", sourceDateEpoch, "+%Y-%m-%dT%H:%M:%SZ")
		return date
	}

	date, _ := sh.Output("date", "+%Y-%m-%dT%H:%M:%SZ")
	return date
}

func generateLDFlags() string {
	pkg := "github.com/Issif/falco-talon/configuration"
	return fmt.Sprintf("-X %[1]s.GitVersion=%[2]s -X %[1]s.gitCommit=%[3]s -X %[1]s.gitTreeState=%[4]s -X %[1]s.buildDate=%[5]s", pkg, getVersion(), getCommit(), getGitState(), getBuildDateTime())
}
