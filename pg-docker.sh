#!/usr/bin/env bash
# =============================================================
#  PhishGuard Docker Manager  (pg-docker.sh)
#  Mirrors pg-git.sh for Docker Hub workflow
# =============================================================

DOCKERHUB_USER="shwnchrlss"   # ← change this
IMAGE_NAME="phishguard"
FULL_IMAGE="$DOCKERHUB_USER/$IMAGE_NAME"

# Read current version from git tag
VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "dev")

echo "╔══════════════════════════════════════╗"
echo "║   🐳  PhishGuard Docker Manager      ║"
echo "╚══════════════════════════════════════╝"
echo "  Image : $FULL_IMAGE"
echo "  Version: $VERSION"
echo ""
echo "  Local"
echo "  1) Build image"
echo "  2) Run stack (docker-compose up)"
echo "  3) Stop stack (docker-compose down)"
echo "  4) Wipe stack + volumes (fresh start)"
echo "  5) Open lazydocker"
echo ""
echo "  Docker Hub"
echo "  6) Login to Docker Hub"
echo "  7) Build + tag + push release"
echo "  8) Pull latest from Docker Hub"
echo ""
echo "  Info"
echo "  9) Show running containers"
echo " 10) Show image sizes"
echo "  0) Exit"
echo ""
read -rp "?  Choose [0-10]: " choice

case $choice in
  1)
    echo "🔨 Building $FULL_IMAGE:$VERSION ..."
    docker build -t "$FULL_IMAGE:$VERSION" -t "$FULL_IMAGE:latest" .
    echo "✅ Build complete"
    ;;
  2)
    docker-compose up -d
    echo "✅ Stack running — http://localhost"
    ;;
  3)
    docker-compose down
    echo "✅ Stack stopped"
    ;;
  4)
    read -rp "⚠️  This deletes ALL data. Type 'yes' to confirm: " confirm
    if [ "$confirm" = "yes" ]; then
      docker-compose down -v
      echo "✅ Stack and volumes wiped"
    else
      echo "Cancelled"
    fi
    ;;
  5)
    ~/.local/bin/lazydocker
    ;;
  6)
    docker login
    ;;
  7)
    echo "🔨 Building $FULL_IMAGE:$VERSION ..."
    docker build -t "$FULL_IMAGE:$VERSION" -t "$FULL_IMAGE:latest" .
    echo "📤 Pushing to Docker Hub..."
    docker push "$FULL_IMAGE:$VERSION"
    docker push "$FULL_IMAGE:latest"
    echo "✅ Pushed $FULL_IMAGE:$VERSION and :latest"
    echo "   https://hub.docker.com/r/$DOCKERHUB_USER/$IMAGE_NAME"
    ;;
  8)
    docker pull "$FULL_IMAGE:latest"
    ;;
  9)
    docker-compose ps
    ;;
  10)
    docker images | grep "$IMAGE_NAME"
    ;;
  0)
    exit 0
    ;;
  *)
    echo "Invalid choice"
    ;;
esac
