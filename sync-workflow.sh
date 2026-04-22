#!/bin/bash
# Script to sync auto-tag workflow from master to target branches

set -e

WORKFLOW_FILE=".github/workflows/auto-tag.yml"
TARGET_BRANCHES=("kernel-backport/main" "kernel-backport/v6.17")

echo "🔄 Syncing auto-tag workflow from master to target branches..."
echo ""

# Ensure we're on master and up to date
git checkout master
git pull origin master

# Check if workflow file exists on master
if [ ! -f "$WORKFLOW_FILE" ]; then
    echo "❌ Error: $WORKFLOW_FILE not found on master branch"
    exit 1
fi

echo "✅ Workflow file found on master"
echo ""

# Sync to each target branch
for branch in "${TARGET_BRANCHES[@]}"; do
    echo "📝 Syncing to $branch..."
    
    # Checkout target branch
    git checkout "$branch"
    git pull origin "$branch"
    
    # Copy workflow from master
    git checkout master -- "$WORKFLOW_FILE"
    
    # Check if there are changes
    if git diff --quiet HEAD "$WORKFLOW_FILE"; then
        echo "   ℹ️  No changes needed for $branch"
    else
        # Commit and push
        git add "$WORKFLOW_FILE"
        git commit -m "github: Sync auto-tag workflow from master"
        git push origin "$branch"
        echo "   ✅ Synced and pushed to $branch"
    fi
    
    echo ""
done

# Return to master
git checkout master

echo "🎉 Workflow sync complete!"
echo ""
echo "Summary:"
for branch in "${TARGET_BRANCHES[@]}"; do
    echo "  ✅ $branch"
done
