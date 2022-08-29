//go:build mage
// +build mage

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func Lint() error {
	if err := sh.RunV("golangci-lint", "run", "--timeout", "3m"); err != nil {
		return err
	}
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}

	return nil
}

func Test() error {
	return sh.RunV("go", "test", "./...", "-race")
}

func BuildLocal() error {
	ldFlags := generateLDFlags()

	fmt.Println(ldFlags)
	return sh.RunV("go", "build", "-trimpath", "-ldflags", ldFlags, "-o", "falco-talon", ".")
}

// BuildImagesLocal build images locally and not push
func BuildImagesLocal() error {
	gitVersion := getVersion()
	gitCommit := getCommit()
	os.Setenv("LDFLAGS", generateLDFlags())

	return sh.RunV("ko", "publish", "--base-import-paths", "--bare", "--local",
		"--platform=linux/amd64", "--tags", gitVersion, "--tags", gitCommit, "--tags", "latest",
		"github.com/Issif/falco-talon")
}

// BuildImages build the images and push
func BuildImages() error {
	gitVersion := getVersion()
	gitCommit := getCommit()
	os.Setenv("LDFLAGS", generateLDFlags())

	if os.Getenv("KO_DOCKER_REPO") == "" {
		return errors.New("missing KO_DOCKER_REPO environment variable")
	}

	return sh.RunV("ko", "publish", "--base-import-paths", "--bare",
		"--platform=linux/amd64", "--tags", gitVersion, "--tags", gitCommit, "--tags", "latest",
		"github.com/Issif/falco-talon")
}

func Build() error {
	os.Setenv("LDFLAGS", generateLDFlags())
	return sh.RunV("goreleaser", "release", "--rm-dist", "--snapshot", "--skip-sign", "--skip-publish")
}

func Release() error {
	mg.Deps(Test)

	os.Setenv("LDFLAGS", generateLDFlags())
	return sh.RunV("goreleaser", "release", "--rm-dist")
}

func Clean() {
	files := []string{"falco-talon", "dist"}

	for _, file := range files {
		sh.Rm(file)
	}
}

// getVersion gets a description of the commit, e.g. v0.30.1 (latest) or v0.30.1-32-gfe72ff73 (canary)
func getVersion() string {
	version, _ := sh.Output("git", "describe", "--tags", "--match=v*")
	if version != "" {
		return version
	}

	// repo without any tags in it
	return "v0.0.0"
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
		date, _ := sh.Output("date", "-u", "-d", sourceDateEpoch, "+'%Y-%m-%dT%H:%M:%SZ'")
		return date
	}

	date, _ := sh.Output("date", "+'%Y-%m-%dT%H:%M:%SZ'")
	return date
}

func generateLDFlags() string {
	pkg := "github.com/Issif/falco-talon/configuration"
	return fmt.Sprintf("-X %[1]s.GitVersion=%[2]s -X %[1]s.gitCommit=%[3]s -X %[1]s.gitTreeState=%[4]s -X %[1]s.buildDate=%[5]s", pkg, getVersion(), getCommit(), getGitState(), getBuildDateTime())
}
