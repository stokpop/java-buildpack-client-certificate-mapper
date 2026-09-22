# Releasing

A release is made from the GitHub UI: publish a release with a new `vX.Y.Z` tag, and the **Release** workflow builds that tag as version `X.Y.Z` and attaches the jars. No version-bump commit or pull request is needed first.

## Versions

Every POM uses `${revision}` as its version. The development value lives in one place, `.mvn/maven.config`:

```
-Drevision=2.1.0-SNAPSHOT
```

A release build overrides it with `-Drevision=X.Y.Z`, taken from the tag. The `flatten-maven-plugin` writes the resolved version into the installed and deployed POMs, so no published POM contains `${revision}`.

The files at a release tag therefore still say `-SNAPSHOT`; the tag name is the record of the version. Do not edit versions in the POMs by hand.

## Making a release

1. GitHub -> **Releases** -> **Draft a new release**.
2. **Choose a tag**: type a new tag `vX.Y.Z` (e.g. `v2.1.0`) and select **Create new tag on publish**, with target `main`.
3. **Generate release notes**, edit as needed.
4. **Publish release**.

The **Release** workflow then:

1. checks the tag has the form `vX.Y.Z`;
2. checks out the tag and runs `./mvnw -Drevision=X.Y.Z verify`, the full test suite included;
3. runs `.github/scripts/check-release-version.sh X.Y.Z`: the jars must be named `X.Y.Z`, every flattened POM must declare `X.Y.Z` with no `${revision}` and no `-SNAPSHOT` version, and the shaded jar's `pom.properties` must record `X.Y.Z`;
4. attaches `java-buildpack-client-certificate-mapper-X.Y.Z.jar` with its `-sources` and `-javadoc` jars to the release.

### When the workflow fails

Nothing is attached. Fix the cause, then either:

- delete the release **and** its tag (Releases -> the release -> Delete; Tags -> the tag -> Delete) and publish again, or
- if the tag is right and only the build failed for an unrelated reason, re-run it: **Actions -> Release -> Run workflow** with the tag (e.g. `v2.1.0`). This rebuilds the tag and replaces the attached artifacts.

## After a release

Nothing has to be merged: `main` keeps building as `-SNAPSHOT`. When convenient, raise `.mvn/maven.config` to the next development version (e.g. `-Drevision=2.1.1-SNAPSHOT`) in a normal pull request; releases do not depend on it.

Automating that bump would need the workflow to push to the protected `main`. It needs a repository admin to allow it, either by letting Actions open pull requests (Settings -> Actions -> General -> *Allow GitHub Actions to create and approve pull requests*) or by giving a GitHub App or deploy key a bypass on the branch protection.

## Rebuilding a release locally

```shell
$ git checkout v2.1.0
$ ./mvnw -Drevision=2.1.0 package
```

## Getting a release into the Java buildpack

The Java buildpack does not take jars from GitHub releases. The Cloud Foundry dependency pipeline ([`buildpacks-ci` `dependency-builds`](https://github.com/cloudfoundry/buildpacks-ci/blob/main/pipelines/dependency-builds/config.yml)) watches **Maven Central** for `org.cloudfoundry:java-buildpack-client-certificate-mapper` (version line `2.X.X`). It rebuilds a new version to `buildpacks.cloudfoundry.org` and opens a pull request on `cloudfoundry/java-buildpack` to update `manifest.yml`.

Publishing to Maven Central requires the `org.cloudfoundry` namespace credentials and signing key, held by the maintainers; `2.0.1` was published that way. The Release workflow marks where a `deploy` step goes once those are available as repository secrets.

The rolling **snapshot** release (updated on every push to `main` by the **CI** workflow) is for testing only.
