#!/usr/bin/env bash
#
# Checks that a release build produced artifacts for exactly one version: the one the release
# tag names. Run from the repository root after `./mvnw -Drevision=<version> verify`.
#
# Usage: .github/scripts/check-release-version.sh 2.1.0

set -euo pipefail

VERSION="${1:-}"
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: expected a release version like 2.1.0, got '${VERSION}'" >&2
  exit 1
fi

MODULE=java-buildpack-client-certificate-mapper
failures=0

fail() {
  echo "ERROR: $*" >&2
  failures=$((failures + 1))
}

# The artifacts attached to the GitHub release.
for suffix in "" "-sources" "-javadoc"; do
  jar="${MODULE}/target/${MODULE}-${VERSION}${suffix}.jar"
  if [[ ! -f "${jar}" ]]; then
    fail "missing ${jar}"
  fi
done

# Every flattened POM must carry the release version, with ${revision} resolved. The benchmark module
# is built only with -Pbenchmarks and never published, so a stale POM there does not count.
poms=$(find . -path '*/target/.flattened-pom.xml' -not -path './.git/*' -not -path "./${MODULE}-benchmark/*")
if [[ -z "${poms}" ]]; then
  fail "no target/.flattened-pom.xml found -- did the build run?"
fi
for pom in ${poms}; do
  if grep -q '\${revision}' "${pom}"; then
    fail "${pom} still contains \${revision}"
  fi
  # Only <version> elements count: the root keeps its <revision> property's development default.
  if grep -q -- '<version>[^<]*-SNAPSHOT</version>' "${pom}"; then
    fail "${pom} contains a -SNAPSHOT version"
  fi
  if ! grep -q "<version>${VERSION}</version>" "${pom}"; then
    fail "${pom} does not declare version ${VERSION}"
  fi
done

# The shaded module publishes the shade plugin's dependency-reduced POM instead of the flattened one.
reduced="${MODULE}/dependency-reduced-pom.xml"
if [[ ! -f "${reduced}" ]]; then
  fail "missing ${reduced}"
else
  if grep -q '\${revision}' "${reduced}"; then
    fail "${reduced} still contains \${revision}"
  fi
  if grep -q -- '<version>[^<]*-SNAPSHOT</version>' "${reduced}"; then
    fail "${reduced} contains a -SNAPSHOT version"
  fi
  if ! grep -q "<version>${VERSION}</version>" "${reduced}"; then
    fail "${reduced} does not declare version ${VERSION}"
  fi
fi

# The version recorded inside the shaded jar.
shaded="${MODULE}/target/${MODULE}-${VERSION}.jar"
if [[ -f "${shaded}" ]]; then
  properties=$(unzip -Z1 "${shaded}" | grep 'META-INF/maven/.*/pom.properties' || true)
  if [[ -z "${properties}" ]]; then
    fail "${shaded} contains no META-INF/maven pom.properties"
  fi
  for entry in ${properties}; do
    recorded=$(unzip -p "${shaded}" "${entry}" | sed -n 's/^version=//p' | tr -d '\r')
    if [[ "${recorded}" != "${VERSION}" ]]; then
      fail "${shaded}!${entry} records version '${recorded}'"
    fi
  done
fi

if (( failures > 0 )); then
  echo "Release version check failed: ${failures} problem(s) for ${VERSION}." >&2
  exit 1
fi
echo "OK: all release artifacts carry version ${VERSION}."
