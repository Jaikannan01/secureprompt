#!/usr/bin/env bash
set -euo pipefail

# SecurePrompt installer
# Usage examples:
#   curl -fsSL https://your.domain/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/<org>/secureprompt/main/scripts/install.sh | bash
#   METHOD=tar REPO_URL=https://github.com/<org>/secureprompt.git bash -c "$(curl -fsSL https://your.domain/install.sh)"

REPO_URL=${REPO_URL:-https://github.com/yourusername/secureprompt.git}
REPO_NAME=${REPO_URL##*/}
DIR=${DIR:-${REPO_NAME%.git}}
BRANCH=${BRANCH:-main}
METHOD=${METHOD:-git} # git|tar
SKIP_BUILD=${SKIP_BUILD:-false}

log() { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m==>\033[0m %s\n" "$*"; }
err() { printf "\033[1;31mERROR:\033[0m %s\n" "$*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "'$1' is required"; exit 1; }
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

log "Checking prerequisites"
need_cmd node
need_cmd npm
need_cmd tar
if [ "$METHOD" = "git" ]; then need_cmd git; fi
if have_cmd curl; then DL="curl -fsSL"; elif have_cmd wget; then DL="wget -qO-"; else err "curl or wget required"; exit 1; fi

log "Installing SecurePrompt ($METHOD)"

if [ -e "$DIR" ]; then
  warn "Target directory '$DIR' already exists; using it as checkout directory."
else
  case "$METHOD" in
    git)
      log "Cloning $REPO_URL (branch: $BRANCH)"
      git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$DIR"
      ;;
    tar)
      # Convert REPO_URL to tarball URL if it's a GitHub repo
      if echo "$REPO_URL" | grep -q "github.com"; then
        ORG_REPO=$(echo "$REPO_URL" | sed -E 's#https?://github.com/([^/]+/[^/.]+)(\.git)?#\1#')
        TARBALL_URL="https://codeload.github.com/$ORG_REPO/tar.gz/refs/heads/$BRANCH"
      else
        err "Automatic tarball URL only supported for GitHub repos. Set TARBALL_URL explicitly."
        exit 1
      fi
      TMPDIR=$(mktemp -d)
      log "Downloading tarball: $TARBALL_URL"
      sh -c "$DL \"$TARBALL_URL\"" | tar -xz -C "$TMPDIR"
      SRC_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -name "*-$BRANCH" | head -n 1)
      mv "$SRC_DIR" "$DIR"
      rm -rf "$TMPDIR"
      ;;
    *)
      err "Unknown METHOD: $METHOD (use 'git' or 'tar')"; exit 1;
      ;;
  esac
fi

cd "$DIR"

log "Installing dependencies"
npm install

if [ "$SKIP_BUILD" != "true" ]; then
  log "Building workspaces"
  npm run build
else
  warn "Skipping build as requested (SKIP_BUILD=true)"
fi

log "Installation complete!"
cat <<EOF

To use the library in your project:
  npm install secureprompt
  # or: pnpm add secureprompt | yarn add secureprompt
EOF

