#!/bin/sh

REPO_DIR="$(pwd)"
WORKTREE_BACKPORT="$REPO_DIR/oot-backport"
WORKTREE_RELEASES="$REPO_DIR/releases"
WORKTREE_KERNEL_SOURCES="$REPO_DIR/kernel-backport"

usage() {
	echo "Usage: $0 [create-worktree|clean-worktree|list-worktree]"
	echo "Commands:"
	echo "  create-worktree   Create git worktree for oot-backport, releases, and kernel-backport branches."
	echo "  clean-worktree    Remove created worktree directories and prune git worktree references."
	echo "  list-worktree     List current git worktree."
	exit 1
}

if [ $# -eq 0 ]; then
	usage
fi

case "$1" in
	create-worktree)
		set -e
		{
			git worktree add "$WORKTREE_BACKPORT" oot-backport/main || { echo "Error: Failed to add worktree for backport/main. Run clean-worktree first"; exit 2; }
			git worktree add "$WORKTREE_RELEASES" releases/main || { echo "Error: Failed to add worktree for releases. Run clean-worktree first"; exit 2; }
			git worktree add "$WORKTREE_KERNEL_SOURCES" kernel-backport/main || { echo "Error: Failed to add worktree for main. Run clean-worktree first"; exit 2; }
		} || { echo "Error: One or more worktree operations failed."; exit 2; }

		echo "Worktree created:"
		git worktree list || { echo "Error: Failed to list worktree."; exit 2; }
		;;
	clean-worktree)
		set -e
		{
			# Remove all the worktree folders
			git worktree remove --force "$WORKTREE_BACKPORT" || echo "Warning: Could not remove $WORKTREE_BACKPORT."
			git worktree remove --force "$WORKTREE_RELEASES" || echo "Warning: Could not remove $WORKTREE_RELEASES."
			git worktree remove --force "$WORKTREE_KERNEL_SOURCES" || echo "Warning: Could not remove $WORKTREE_KERNEL_SOURCES."

			git worktree prune || echo "Warning: Failed to prune worktree."

			rm -rf "$WORKTREE_BACKPORT" "$WORKTREE_RELEASES" "$WORKTREE_KERNEL_SOURCES"
		} || { echo "Error: One or more clean operations failed."; exit 2; }

		echo "Worktree cleaned."
		git worktree list || { echo "Error: Failed to list worktree."; exit 2; }
		;;
	list-worktree)
		echo "Current git worktree:"
		git worktree list || { echo "Error: Failed to list worktree."; exit 2; }
		;;
	*)
		usage
		;;
esac
