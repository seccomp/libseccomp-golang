The libseccomp-golang Release Process
===============================================================================
https://github.com/seccomp/libseccomp-golang

This is the process that should be followed when creating a new
libseccomp-golang release.

#### 1. Verify that all issues assigned to the release milestone have been resolved

  * https://github.com/seccomp/libseccomp-golang/milestones

#### 2. Verify that the syntax/style meets the guidelines

	% make check-syntax

#### 3. Verify that the bundled tests run without error

	% make vet
	% make check

#### 4. If any problems were found up to this point that resulted in code changes, restart the process

#### 5. Update the CHANGELOG file with significant changes since the last release

#### 6. If this is a new major/minor release, create new 'release-X.Y' branch

	% stg branch -c "release-X.Y"

	... or ...

	% git branch "release-X.Y"

#### 7. Tag the release in the local repository with a signed tag

	% git tag -s -m "version X.Y.Z" vX.Y.Z

#### 8. Push the release tag to the main GitHub repository

	% git push <repo> vX.Y.Z

#### 9. Create a new GitHub release using the associated tag, add the relevant section from the CHANGELOG file

#### 19. Update the GitHub release notes for older releases which are now unsupported

The following Markdown text is suggested at the top of the release note, see old GitHub releases for examples.

```
***This release is no longer supported upstream, please use a more recent release***
```
