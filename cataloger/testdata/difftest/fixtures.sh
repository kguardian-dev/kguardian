#!/usr/bin/env bash
# Build the differential-test fixtures: each image unpacked to a directory
# under OUTDIR, plus synthetic variants with merged-/usr and symlinked
# package-database directories. Nothing is committed: images are pulled
# (or built from ./images) at test time.
#
#   fixtures.sh OUTDIR [name ...]      (default: every fixture)
#
# Needs docker, curl and python3. Creates and removes only its own
# containers (kgc-fx-<name>) and images (kgc-fx-<name>:difftest).
set -euo pipefail

out=${1:?usage: fixtures.sh OUTDIR [name ...]}
shift
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"

# name -> image. Tags are pinned to a release line, not a digest: the gate
# is "our resolver == Syft's directory source", which holds for any
# content, and a moving tag keeps exercising what users run.
declare -A images=(
  [alpine]=alpine:3.20
  [debian]=debian:12-slim
  [ubi-minimal]=registry.access.redhat.com/ubi9/ubi-minimal:latest
  [distroless]=gcr.io/distroless/base-debian12:latest
  [python]=python:3.12-slim
  [node]=node:22-alpine
)
# static-go and rust-auditable are built from ./images/<name>/Dockerfile;
# spring-boot and the symlinked-* ones are derived from other fixtures.
all=(alpine debian ubi-minimal distroless static-go rust-auditable spring-boot python node symlinked-apk-db symlinked-dpkg-db)
want=("$@")
[ ${#want[@]} -eq 0 ] && want=("${all[@]}")

export_image() { # name image
  local name=$1 image=$2 dir=$out/$1
  rm -rf "$dir"
  mkdir -p "$dir"
  docker rm -f "kgc-fx-$name" >/dev/null 2>&1 || true
  docker create --name "kgc-fx-$name" "$image" /nonexistent >/dev/null
  # Device nodes cannot be created unprivileged and never matter here.
  docker export "kgc-fx-$name" | tar -x -C "$dir" --no-same-owner --exclude='dev/*'
  docker rm "kgc-fx-$name" >/dev/null
  echo "fixture $name: $(find "$dir" | wc -l) entries from $image"
}

need() { # fixture needed by a synthetic one
  [ -d "$out/$1" ] || build "$1"
}

build() {
  local name=$1
  if [ -n "${images[$name]:-}" ]; then
    docker pull -q "${images[$name]}" >/dev/null
    export_image "$name" "${images[$name]}"
    return
  fi
  case $name in
    static-go | rust-auditable)
      docker build -q -t "kgc-fx-$name:difftest" "$here/images/$name" >/dev/null
      export_image "$name" "kgc-fx-$name:difftest"
      docker rmi "kgc-fx-$name:difftest" >/dev/null
      ;;
    spring-boot)
      # A Spring Boot layout fat jar (BOOT-INF/lib nested jars) on alpine:
      # Syft must unpack the nested jars into its temp dir to find them,
      # which is the reason the resolver is (a) and not chroot.
      need alpine
      rm -rf "$out/$name"
      cp -a "$out/alpine" "$out/$name"
      mkdir -p "$out/$name/app"
      python3 "$here/fatjar.py" "$out/$name/app/app.jar"
      echo "fixture $name: fat jar $(du -h "$out/$name/app/app.jar" | cut -f1)"
      ;;
    symlinked-apk-db)
      # lib/apk/db is a relative symlink to another directory, and
      # etc/os-release an absolute one that climbs with "..": both must
      # resolve inside the root.
      need alpine
      rm -rf "$out/$name"
      cp -a "$out/alpine" "$out/$name"
      mkdir -p "$out/$name/var/lib/apk-store"
      mv "$out/$name/lib/apk/db" "$out/$name/var/lib/apk-store/db"
      ln -s ../../var/lib/apk-store/db "$out/$name/lib/apk/db"
      mv "$out/$name/etc/os-release" "$out/$name/usr/share/os-release.real"
      ln -s /../../../usr/share/os-release.real "$out/$name/etc/os-release"
      echo "fixture $name: lib/apk/db -> ../../var/lib/apk-store/db"
      ;;
    symlinked-dpkg-db)
      # var/lib/dpkg is an absolute symlink (resolved against the root, not
      # the host) on a merged-/usr debian.
      need debian
      rm -rf "$out/$name"
      cp -a "$out/debian" "$out/$name"
      mkdir -p "$out/$name/opt"
      mv "$out/$name/var/lib/dpkg" "$out/$name/opt/dpkg-store"
      ln -s /opt/dpkg-store "$out/$name/var/lib/dpkg"
      echo "fixture $name: var/lib/dpkg -> /opt/dpkg-store"
      ;;
    *)
      echo "unknown fixture $name" >&2
      exit 2
      ;;
  esac
}

for n in "${want[@]}"; do
  build "$n"
done
