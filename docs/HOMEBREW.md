# Homebrew Distribution

This project is distributed through a dedicated Homebrew tap:

```text
github.com/hciupinski/homebrew-resistack
```

Homebrew maps that repository to the tap name:

```text
hciupinski/resistack
```

## User Install Command

Users can install ResistanceStack without manually adding the tap first:

```bash
brew install hciupinski/resistack/resistack
```

This is the supported one-command custom tap install.

If users add the tap explicitly once:

```bash
brew tap hciupinski/resistack
brew install resistack
```

then later upgrades use the short formula name:

```bash
brew update
brew upgrade resistack
```

Important: `brew install resistack` without a tap prefix works only after either:

- the user already ran `brew tap hciupinski/resistack`, or
- the formula is accepted into Homebrew Core.

## Release Flow

The production release flow is automated through GoReleaser. See [RELEASE_FLOW.md](RELEASE_FLOW.md) for the full branch, PR, tag, and secret setup.

Manual formula updates are only needed if you are not using the automated release workflow.

## Manual Formula Flow

1. Ensure the app repo is clean and tests pass:

```bash
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

2. Create and push a version tag from the app repo:

```bash
git tag v0.1.0
git push origin v0.1.0
```

3. Compute the source archive SHA256:

```bash
curl -L -o resistack-v0.1.0.tar.gz \
  https://github.com/hciupinski/resistancestack/archive/refs/tags/v0.1.0.tar.gz

shasum -a 256 resistack-v0.1.0.tar.gz
```

4. In `hciupinski/homebrew-resistack`, create or update:

```text
Formula/resistack.rb
```

Use the source-build template from:

```text
packaging/homebrew/Formula/resistack.rb.template
```

The automated GoReleaser flow generates a binary-install formula directly into the tap and does not use this template.

5. Validate the tap formula locally:

```bash
brew install --build-from-source ./Formula/resistack.rb
brew test resistack
brew audit --strict --online resistack
```

6. Commit and push the tap:

```bash
git add Formula/resistack.rb
git commit -m "Update resistack to v0.1.0"
git push origin main
```

7. Verify install from the tap:

```bash
brew uninstall resistack
brew untap hciupinski/resistack
brew install hciupinski/resistack/resistack
resistack --help
```

## Tap Repository Layout

The tap repository should look like this:

```text
homebrew-resistack/
└── Formula/
    └── resistack.rb
```

## Formula Naming

The formula class must be:

```ruby
class Resistack < Formula
```

The file must be:

```text
Formula/resistack.rb
```

This is what makes `brew install hciupinski/resistack/resistack` resolve correctly.

## Future Homebrew Core Flow

To support exactly:

```bash
brew install resistack
```

for users who never tapped your repository, submit the formula to `Homebrew/homebrew-core`.

Before doing that, the project should have:

- stable tagged releases,
- a public license,
- a non-placeholder homepage,
- tests in the formula,
- no dependency on building from an unstable branch,
- enough adoption to justify inclusion.
