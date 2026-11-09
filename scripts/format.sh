#!/bin/sh
# SPDX-License-Identifier: MIT
# Check or fix the formatting of the analyzer and the pipeline against .editorconfig.
#
#   scripts/format.sh                 check everything (whitespace, code style, analyzers); changes nothing
#   scripts/format.sh --fix           apply every fix dotnet format can make
#   scripts/format.sh --whitespace    check whitespace only: faster, and works where the full check
#                                     cannot (a sandbox that blocks dotnet format's build host)
#   scripts/format.sh --whitespace --fix
#
# Exits 0 when everything is clean (or was fixed), 1 when the check found something to fix,
# 2 on bad usage, 3 when dotnet format itself failed to run.
# Fixtures are not checked: they hold code written to be flagged and are exempt from the analyzers.
set -u

fix=0
whitespace=0
for arg in "$@"; do
    case "$arg" in
        --fix) fix=1 ;;
        --whitespace) whitespace=1 ;;
        -h|--help) sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "format.sh: unknown option '$arg' (try --help)" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.." || exit 3
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

verify="--verify-no-changes"
[ "$fix" = 1 ] && verify=""

found=0
broken=0
for project in src/DarkMatter/DarkMatter.csproj src/DarkMatter.Pipeline/DarkMatter.Pipeline.csproj; do
    if [ "$whitespace" = 1 ]; then
        echo "== whitespace: $(dirname "$project")"
        # shellcheck disable=SC2086
        dotnet format whitespace --folder "$(dirname "$project")" $verify
    else
        echo "== whitespace, style and analyzers: $project"
        # shellcheck disable=SC2086
        dotnet format "$project" $verify
    fi
    # dotnet format exits 2 when --verify-no-changes finds something, and 1 when it fails to run.
    case $? in
        0) ;;
        2) found=1 ;;
        *) broken=1 ;;
    esac
done

if [ "$broken" = 1 ]; then
    echo "dotnet format failed to run (see above). If it could not connect to its build host's pipe," >&2
    echo "the environment blocks it (a sandbox): run this outside it, or use --whitespace." >&2
    exit 3
fi
if [ "$found" = 1 ]; then
    hint="--fix"
    [ "$whitespace" = 1 ] && hint="--whitespace --fix"
    echo "format check failed: run scripts/format.sh $hint to apply the fixes" >&2
    exit 1
fi
if [ "$fix" = 1 ]; then echo "formatted"; else echo "format check passed"; fi
exit 0
