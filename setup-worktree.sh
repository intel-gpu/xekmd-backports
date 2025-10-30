#!/bin/sh

REPO_DIR="$(pwd)"
WORKTREE_BACKPORT="$REPO_DIR/oot-backport"
WORKTREE_RELEASES="$REPO_DIR/releases"
WORKTREE_KERNEL_SOURCES="$REPO_DIR/kernel-backport"

usage() {
	echo "Usage: $0 [create-worktree|clean-worktree|list-worktree|kernel-backport-only|oot-release-only]"
	echo "Commands:"
	echo "  create-worktree       Create git worktree for oot-backport, releases, and kernel-backport branches and generate the base kernel."
	echo "  clean-worktree        Remove created worktree directories and prune git worktree references."
	echo "  list-worktree         List current git worktree."
	echo "  kernel-backport-only  Create only the base kernel inside kernel-backport worktree."
	echo "  oot-release-only      Traverse to release worktree and checkout to oot-backport release."
	exit 1
}

if [ $# -eq 0 ]; then
	# Default to create-worktree when no arguments are provided
	set -- create-worktree
fi

# generate_kernel()
# runs the backport.sh inside the kernel worktree
# by-default we are traversing into the generated kernel through an interactive shell
generate_kernel() {
	if [ ! -x "$WORKTREE_KERNEL_SOURCES/backport.sh" ]; then
		echo "Error: $WORKTREE_KERNEL_SOURCES/backport.sh not found or not executable"
		return 2
	fi

	(
		cd "$WORKTREE_KERNEL_SOURCES" && ./backport.sh
	) || { echo "Error: backport.sh failed"; return 3; }

	if [ -d "$WORKTREE_KERNEL_SOURCES/kernel" ]; then
		if [ "${SKIP_INTERACTIVE:-}" = "1" ]; then
			echo "Generated kernel at: $WORKTREE_KERNEL_SOURCES/kernel"
			return 0
		else
			# Interactive mode
			if cd "$WORKTREE_KERNEL_SOURCES/kernel"; then
				exec "${SHELL:-/bin/sh}" -i
			else
				echo "Error: failed to move to $WORKTREE_KERNEL_SOURCES/kernel"
				return 4
			fi
		fi
	else
		echo "Warning: expected kernel directory not found in $WORKTREE_KERNEL_SOURCES"
		return 5
	fi
}

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

		# Generate the base kernel from the kernel-backport worktree
		generate_kernel || { echo "Kernel generation failed or was skipped"; exit 3; }
		;;
	kernel-backport-only)
		git worktree add "$WORKTREE_KERNEL_SOURCES" kernel-backport/main || { echo "Error: Failed to add worktree for backport/main. Run clean-worktree first"; exit 2; }
		# Generate the base kernel from the kernel-backport worktree
		generate_kernel || { echo "Kernel generation failed or was skipped"; exit 3; }
		;;
	oot-release-only)
		git worktree add "$WORKTREE_RELEASES" releases/main || { echo "Error: Failed to add worktree for releases. Run clean-worktree first"; exit 2; }
		if cd "$WORKTREE_RELEASES"; then
			exec "${SHELL:-/bin/sh}" -i
		else
			echo "Error: failed to move to $WORKTREE_RELEASES"
		fi
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
