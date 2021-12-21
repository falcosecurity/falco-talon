//go:build mage
// +build mage

package main

import (
	"errors"
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

	return sh.RunV("git", "diff", "--exit-code")
}

func Test() error {
	return sh.RunV("go", "test", "./...", "-race")
}

func BuildLocal() error {
	return sh.RunV("go", "build", "-trimpath", "-o", "falco-talon", "./cmd/server")
}

// BuildImagesLocal build images locally and not push
func BuildImagesLocal() error {
	gitVersion := getVersion()
	gitCommit := getCommit()

	return sh.RunV("ko", "publish", "--base-import-paths", "--bare", "--local",
		"--platform=all", "--tags", gitVersion, "--tags", gitCommit,
		"github.com/Issif/falco-talon/cmd/server")
}

// BuildImages build the images and push
func BuildImages() error {
	gitVersion := getVersion()
	gitCommit := getCommit()

	if os.Getenv("KO_PREFIX") == "" {
		return errors.New("missing KO_PREFIX environment variable")
	}

	return sh.RunV("ko", "publish", "--base-import-paths", "--bare",
		"--platform=all", "--tags", gitVersion, "--tags", gitCommit,
		"github.com/Issif/falco-talon/cmd/server")
}

func Build() error {
	return sh.RunV("goreleaser", "release", "--rm-dist", "--snapshot", "--skip-sign", "--skip-publish")
}

func Release() error {
	mg.Deps(Test)

	return sh.RunV("goreleaser", "release", "--rm-dist")
}

func Clean() {
	files := []string{"falco-talon", "dist"}

	for _, file := range files {
		sh.Rm(file)
	}
}

// Get a description of the commit, e.g. v0.30.1 (latest) or v0.30.1-32-gfe72ff73 (canary)
func getVersion() string {
	version, _ := sh.Output("git", "describe", "--tags", "--match=v*")
	if version != "" {
		return version
	}

	// repo without any tags in it
	return "v0.0.0"
}

// Get the hash of the current commit
func getCommit() string {
	commit, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return commit
}
