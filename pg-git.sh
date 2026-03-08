#!/usr/bin/env bash
# =============================================================
#  pg-git.sh — PhishGuard Git Workflow Automation
#  Place this in: ~/code/phishguard/
#  Make executable: chmod +x pg-git.sh
#  Run with: ./pg-git.sh
#
#  CONCEPT: Shell scripting automation
#  This script wraps common git commands into a menu-driven
#  interface. It prompts you for the human parts (messages,
#  branch names) and handles the repetitive git commands.
# =============================================================

set -e  # Exit immediately if any command fails

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No colour

# ── Helpers ───────────────────────────────────────────────────
info()    { echo -e "${CYAN}ℹ  $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $1${NC}"; }
error()   { echo -e "${RED}✗  $1${NC}"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..50})${NC}"; }

# ── Confirm prompt ────────────────────────────────────────────
confirm() {
  read -rp "$(echo -e "${YELLOW}?  $1 [y/N]: ${NC}")" ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ── Get current branch ────────────────────────────────────────
# On a brand-new repo with zero commits, HEAD exists but points
# to nothing yet. rev-parse returns "HEAD" literally in that case.
# We detect this and return the branch name from .git/HEAD instead.
current_branch() {
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
  # "HEAD" means detached or zero-commit state — read raw ref
  if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
    branch=$(cat "$(git rev-parse --git-dir)/HEAD" 2>/dev/null | sed 's|ref: refs/heads/||')
  fi
  echo "${branch:-dev}"
}

# ── Check if repo has any commits ────────────────────────────
has_commits() {
  git rev-parse HEAD &>/dev/null
}

# ── Show repo status ──────────────────────────────────────────
show_status() {
  header "📊 Repository Status"
  echo -e "${BOLD}Branch:${NC}  $(current_branch)"
  echo -e "${BOLD}Remote:${NC}  $(git remote get-url origin 2>/dev/null || echo 'not set')"
  echo ""
  git status --short
  echo ""
  info "Recent commits:"
  git log --oneline -5 2>/dev/null || echo "No commits yet."
  echo ""
}

# ── Save current work (add + commit) ─────────────────────────
save_work() {
  header "💾 Save Current Work"

  # ── First-commit detection ──────────────────────────────────
  # On a brand-new repo there are no commits yet. Detect this
  # and guide through the initial commit + GitHub push in one go.
  if ! has_commits; then
    warn "No commits yet — this will be your FIRST commit."
    echo ""
    echo -e "  ${BOLD}What happens:${NC}"
    echo "  1. All your files get committed to dev"
    echo "  2. A main branch is created from dev"
    echo "  3. Both branches are pushed to GitHub"
    echo ""
    confirm "Proceed with initial commit?" || { warn "Cancelled."; return; }

    git add .
    git commit -m "feat: initial PhishGuard application"

    # Push dev first (we are already on dev)
    git push -u origin dev

    # Create main from dev and push it
    git checkout -b main
    git push -u origin main

    # Return to dev for all future work
    git checkout dev

    success "Initial commit done. Both branches live on GitHub."
    info "View: $(git remote get-url origin | sed 's/\.git$//')"
    return
  fi

  # Show what's changed
  echo -e "${BOLD}Changed files:${NC}"
  git status --short
  echo ""

  if [[ -z "$(git status --porcelain)" ]]; then
    warn "No changes to save. Working tree is clean."
    return
  fi

  # Choose what to stage
  echo -e "${BOLD}What to include?${NC}"
  echo "  1) Everything (git add .)"
  echo "  2) Choose files interactively (git add -p)"
  echo "  3) Specific files (you type them)"
  read -rp "$(echo -e "${YELLOW}?  Choice [1]: ${NC}")" stage_choice
  stage_choice=${stage_choice:-1}

  case $stage_choice in
    1) git add . ;;
    2) git add -p ;;
    3)
      read -rp "$(echo -e "${YELLOW}?  Files (space-separated): ${NC}")" files
      git add $files
      ;;
    *) git add . ;;
  esac

  # Commit type
  echo ""
  echo -e "${BOLD}Commit type:${NC}"
  echo "  1) feat     — new feature"
  echo "  2) fix      — bug fix"
  echo "  3) refactor — code cleanup"
  echo "  4) style    — CSS / formatting"
  echo "  5) docs     — documentation"
  echo "  6) test     — tests"
  echo "  7) chore    — config, dependencies"
  read -rp "$(echo -e "${YELLOW}?  Type [1]: ${NC}")" type_choice
  type_choice=${type_choice:-1}

  case $type_choice in
    1) commit_type="feat" ;;
    2) commit_type="fix" ;;
    3) commit_type="refactor" ;;
    4) commit_type="style" ;;
    5) commit_type="docs" ;;
    6) commit_type="test" ;;
    7) commit_type="chore" ;;
    *) commit_type="feat" ;;
  esac

  # Commit message
  echo ""
  read -rp "$(echo -e "${YELLOW}?  Short description (e.g. 'add email detail panel'): ${NC}")" short_msg
  if [[ -z "$short_msg" ]]; then
    error "Commit message cannot be empty."
  fi

  read -rp "$(echo -e "${YELLOW}?  Longer explanation? (Enter to skip): ${NC}")" long_msg

  # Build full message
  full_msg="${commit_type}: ${short_msg}"
  if [[ -n "$long_msg" ]]; then
    full_msg="${full_msg}

${long_msg}"
  fi

  echo ""
  info "Commit message: ${full_msg}"
  confirm "Commit with this message?" || { warn "Cancelled."; return; }

  git commit -m "$full_msg"
  success "Committed: ${commit_type}: ${short_msg}"
}

# ── Push to GitHub ────────────────────────────────────────────
push_changes() {
  header "🚀 Push to GitHub"
  branch=$(current_branch)
  info "Pushing branch: ${branch}"

  # Check if upstream exists
  if ! git rev-parse --abbrev-ref "@{upstream}" &>/dev/null; then
    warn "No upstream set. Setting upstream to origin/${branch}."
    git push --set-upstream origin "$branch"
  else
    git push origin "$branch"
  fi

  success "Pushed to origin/${branch}"
  echo ""
  info "View on GitHub: $(git remote get-url origin | sed 's/\.git$//')/tree/${branch}"
}

# ── Start a new feature branch ────────────────────────────────
new_feature() {
  header "🌿 Start New Feature Branch"

  echo -e "${BOLD}Branch type:${NC}"
  echo "  1) feature  — new functionality"
  echo "  2) fix      — bug fix"
  echo "  3) refactor — code improvement"
  echo "  4) experiment — trying something out"
  read -rp "$(echo -e "${YELLOW}?  Type [1]: ${NC}")" btype_choice

  case ${btype_choice:-1} in
    1) prefix="feature" ;;
    2) prefix="fix" ;;
    3) prefix="refactor" ;;
    4) prefix="experiment" ;;
    *) prefix="feature" ;;
  esac

  read -rp "$(echo -e "${YELLOW}?  Feature name (e.g. gmail-integration): ${NC}")" fname
  if [[ -z "$fname" ]]; then
    error "Branch name cannot be empty."
  fi

  # Sanitise: lowercase, spaces to hyphens
  fname=$(echo "$fname" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
  branch_name="${prefix}/${fname}"

  info "Creating branch: ${branch_name} from $(current_branch)"
  confirm "Proceed?" || { warn "Cancelled."; return; }

  # Block if no commits — stash and branch need at least one commit
  if ! has_commits; then
    warn "You need at least one commit before creating feature branches."
    warn "Run option 2 (Save work) first to make your initial commit."
    return
  fi

  # Save any uncommitted work first
  if [[ -n "$(git status --porcelain)" ]]; then
    warn "You have uncommitted changes. Stashing them..."
    git stash push -m "auto-stash before creating ${branch_name}"
    info "Stashed. Run 'git stash pop' to restore after switching."
  fi

  git checkout -b "$branch_name"
  success "Now on branch: ${branch_name}"
  info "When done: use 'Merge feature into dev' from the menu."
}

# ── Merge feature into dev ────────────────────────────────────
merge_to_dev() {
  header "🔀 Merge Feature into Dev"

  current=$(current_branch)
  if [[ "$current" == "main" || "$current" == "dev" ]]; then
    warn "You're on '${current}'. Switch to your feature branch first."
    return
  fi

  info "Will merge: ${current} → dev"
  confirm "Proceed?" || { warn "Cancelled."; return; }

  # Ensure feature is committed
  if [[ -n "$(git status --porcelain)" ]]; then
    warn "You have uncommitted changes. Save them first (option 2)."
    return
  fi

  git checkout dev
  git pull origin dev 2>/dev/null || true
  git merge "$current" --no-ff -m "merge: ${current} into dev"
  git push origin dev

  success "Merged ${current} into dev and pushed."

  if confirm "Delete the feature branch ${current}?"; then
    git branch -d "$current"
    git push origin --delete "$current" 2>/dev/null || true
    success "Branch ${current} deleted."
  fi
}

# ── Release: merge dev into main and tag ─────────────────────
release() {
  header "🏷  Release — Merge Dev into Main"

  current=$(current_branch)
  if [[ "$current" != "dev" ]]; then
    warn "Switch to 'dev' branch first before releasing."
    return
  fi

  # Get current version from tags
  last_tag=$(git tag --sort=-version:refname 2>/dev/null | head -1)
  last_tag=${last_tag:-v0.0.0}
  info "Last release tag: ${last_tag}"

  echo ""
  echo -e "${BOLD}Version bump type:${NC}"
  echo "  1) patch  — bug fixes only          (v1.0.0 → v1.0.1)"
  echo "  2) minor  — new features, backwards compatible (v1.0.0 → v1.1.0)"
  echo "  3) major  — breaking changes        (v1.0.0 → v2.0.0)"
  read -rp "$(echo -e "${YELLOW}?  Type [1]: ${NC}")" bump_choice

  # Parse last tag
  IFS='.' read -r maj min pat <<< "${last_tag#v}"
  case ${bump_choice:-1} in
    1) pat=$((pat + 1)) ;;
    2) min=$((min + 1)); pat=0 ;;
    3) maj=$((maj + 1)); min=0; pat=0 ;;
  esac
  new_tag="v${maj}.${min}.${pat}"

  read -rp "$(echo -e "${YELLOW}?  Release notes (what's in this version?): ${NC}")" notes

  info "Releasing ${new_tag}: ${notes}"
  confirm "Merge dev → main and tag ${new_tag}?" || { warn "Cancelled."; return; }

  git checkout main
  git pull origin main 2>/dev/null || true
  git merge dev --no-ff -m "release: ${new_tag} — ${notes}"
  git tag -a "$new_tag" -m "${notes}"
  git push origin main
  git push origin --tags

  git checkout dev
  success "Released ${new_tag} to main."
  info "View releases: $(git remote get-url origin | sed 's/\.git$//')/releases"
}

# ── Pull latest from GitHub ───────────────────────────────────
pull_latest() {
  header "⬇  Pull Latest from GitHub"
  branch=$(current_branch)
  info "Pulling origin/${branch}..."
  git pull origin "$branch"
  success "Up to date with origin/${branch}"
}

# ── View git log nicely ───────────────────────────────────────
view_log() {
  header "📜 Commit History"
  if ! has_commits; then
    warn "No commits yet. Use option 2 to make your first commit."
    return
  fi
  git log --oneline --graph --decorate --all -20
}

# ── Setup: initialise repo and connect to GitHub ──────────────
setup_github() {
  header "⚙  Setup GitHub Connection"

  if git remote get-url origin &>/dev/null; then
    info "Remote already set: $(git remote get-url origin)"
    confirm "Replace it?" || return
    git remote remove origin
  fi

  echo ""
  echo "Steps to get your GitHub URL:"
  echo "  1. Go to github.com → New repository"
  echo "  2. Name it 'phishguard' → Create (don't initialise with README)"
  echo "  3. Copy the SSH or HTTPS URL shown"
  echo ""
  read -rp "$(echo -e "${YELLOW}?  Paste your GitHub repo URL: ${NC}")" repo_url

  if [[ -z "$repo_url" ]]; then
    error "URL cannot be empty."
  fi

  git remote add origin "$repo_url"
  success "Remote set to: ${repo_url}"

  # Cannot create branches or push without at least one commit.
  # Direct the user to option 2 which handles the initial commit
  # and first push in one guided flow.
  if ! has_commits; then
    echo ""
    warn "Remote is set but you have no commits yet."
    info "→ Go back to the menu and choose option 2 (Save work)."
    info "  It will make your first commit and push everything to GitHub."
    return
  fi

  # Already have commits — just ensure branches exist and push
  git checkout -B main 2>/dev/null || true
  if ! git rev-parse dev &>/dev/null 2>&1; then
    git checkout -b dev
    git checkout main
    info "Created dev branch."
  fi

  info "Pushing to GitHub..."
  git push -u origin main
  git push -u origin dev 2>/dev/null || true

  success "Repository connected to GitHub!"
  info "URL: ${repo_url}"
}

# ── Create .gitignore if missing ──────────────────────────────
ensure_gitignore() {
  gitignore="$(git rev-parse --show-toplevel)/.gitignore"
  if [[ ! -f "$gitignore" ]]; then
    info "Creating .gitignore..."
    cat > "$gitignore" << 'EOF'
# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
.eggs/

# Virtual environment
.venv/
venv/
env/

# Environment / secrets — NEVER commit these
.env
*.env
credentials.json
token.json
secrets.json

# Database — contains real user data
*.db
*.sqlite
*.sqlite3
instance/

# ML model files — large, rebuild from training
backend/ml/saved_models/*.pkl
backend/ml/saved_models/*.joblib

# Logs
*.log
logs/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Node (if frontend build tools added later)
node_modules/
EOF
    git add .gitignore
    success ".gitignore created."
  fi
}

# ── Main menu ─────────────────────────────────────────────────
# ── Delete merged branches ────────────────────────────────────
# Lists all local branches except main and dev, lets user
# pick one or more to delete locally and on GitHub.
delete_branches() {
  header "🗑  Delete Merged Branches"

  if ! has_commits; then
    warn "No commits yet — nothing to delete."
    return
  fi

  # Collect all branches except main, dev, and current
  local current
  current=$(current_branch)

  # Build list excluding protected branches
  mapfile -t branches < <(
    git branch --format='%(refname:short)' \
    | grep -vE '^(main|dev)$' \
    | grep -v "^${current}$"
  )

  if [[ ${#branches[@]} -eq 0 ]]; then
    warn "No branches to delete (only main/dev and current branch exist)."
    return
  fi

  # Show numbered list
  echo -e "${BOLD}Available branches to delete:${NC}"
  echo -e "${DIM}(main and dev are protected — never deleted)${NC}"
  echo ""
  for i in "${!branches[@]}"; do
    local b="${branches[$i]}"
    # Check if merged into dev
    if git branch --merged dev 2>/dev/null | grep -q "^\s*${b}$"; then
      echo "  $((i+1))) ${b} ${GREEN}[merged into dev ✓]${NC}"
    else
      echo "  $((i+1))) ${b} ${YELLOW}[NOT merged — deleting loses work]${NC}"
    fi
  done
  echo ""
  echo "  a) Delete ALL merged branches at once"
  echo "  0) Cancel"
  echo ""

  read -rp "$(echo -e "${YELLOW}?  Choose number(s), 'a' for all, or 0 to cancel: ${NC}")" choice

  case "$choice" in
    0)
      warn "Cancelled."
      return
      ;;

    a)
      # Delete only merged branches automatically
      local merged=()
      for b in "${branches[@]}"; do
        if git branch --merged dev 2>/dev/null | grep -q "^\s*${b}$"; then
          merged+=("$b")
        fi
      done

      if [[ ${#merged[@]} -eq 0 ]]; then
        warn "No merged branches found to delete."
        return
      fi

      echo ""
      echo -e "${BOLD}Will delete these merged branches:${NC}"
      for b in "${merged[@]}"; do echo "  • $b"; done
      echo ""
      confirm "Delete all of the above?" || { warn "Cancelled."; return; }

      for b in "${merged[@]}"; do
        git branch -d "$b" && \
          git push origin --delete "$b" 2>/dev/null && \
          success "Deleted: $b (local + remote)" || \
          warn "Could not fully delete: $b"
      done
      ;;

    *)
      # Parse comma or space separated numbers e.g. "1 3" or "1,3"
      local selections
      IFS=', ' read -ra selections <<< "$choice"

      for sel in "${selections[@]}"; do
        # Validate it's a number in range
        if ! [[ "$sel" =~ ^[0-9]+$ ]] || \
           [[ "$sel" -lt 1 ]] || \
           [[ "$sel" -gt ${#branches[@]} ]]; then
          warn "Invalid selection: $sel — skipping"
          continue
        fi

        local b="${branches[$((sel-1))]}"

        # Warn if not merged
        if ! git branch --merged dev 2>/dev/null | grep -q "^\s*${b}$"; then
          warn "${b} is NOT merged into dev. Deleting will lose its commits."
          confirm "Delete anyway?" || { warn "Skipped: $b"; continue; }
          # Force delete unmerged branch
          git branch -D "$b"
        else
          git branch -d "$b"
        fi

        # Delete remote
        if git push origin --delete "$b" 2>/dev/null; then
          success "Deleted: $b (local + remote)"
        else
          success "Deleted: $b (local only — not on remote)"
        fi
      done
      ;;
  esac

  echo ""
  info "Remaining branches:"
  git branch -a
}

# ── Main menu ─────────────────────────────────────────────────
main_menu() {
  while true; do
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║     🛡  PhishGuard Git Manager       ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════╝${NC}"
    echo -e "  Branch: ${GREEN}$(current_branch)${NC}"
    echo ""
    echo -e "  ${BOLD}Daily workflow${NC}"
    echo "  1) Show status"
    echo "  2) Save work (add + commit)"
    echo "  3) Push to GitHub"
    echo "  4) Pull latest from GitHub"
    echo ""
    echo -e "  ${BOLD}Feature workflow${NC}"
    echo "  5) Start new feature branch"
    echo "  6) Merge feature into dev"
    echo "  7) Release dev → main (with version tag)"
    echo ""
    echo -e "  ${BOLD}Info${NC}"
    echo "  8) View commit history"
    echo "  9) Setup GitHub connection"
    echo "  10) Delete merged branches"
    echo "  0) Exit"
    echo ""
    read -rp "$(echo -e "${YELLOW}?  Choose [0-10]: ${NC}")" choice

    case $choice in
      1)  show_status ;;
      2)  save_work ;;
      3)  push_changes ;;
      4)  pull_latest ;;
      5)  new_feature ;;
      6)  merge_to_dev ;;
      7)  release ;;
      8)  view_log ;;
      9)  setup_github ;;
      10) delete_branches ;;
      0)  echo -e "${GREEN}Goodbye.${NC}"; exit 0 ;;
      *)  warn "Invalid choice. Enter 0-10." ;;
    esac
  done
}

# ── Entry point ───────────────────────────────────────────────
# Must be run from inside the phishguard directory
if ! git rev-parse --git-dir &>/dev/null; then
  error "Not a git repository. Run 'git init' first or cd into your project."
fi

ensure_gitignore
main_menu
