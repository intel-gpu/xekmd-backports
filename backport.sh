#!/bin/bash

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
. "$SCRIPT_DIR/config"
KERNEL_TAG="$BASELINE"

# Linux
wget=/usr/bin/wget
tar=/bin/tar
WORKING_DIR="$PWD"
TIME_STAMP=$(date +%Y%m%d_%H%M%S)

KERNEL_BASE="https://git.kernel.org/torvalds/t/"
KERNEL="linux-${KERNEL_TAG/v}"

SHORT=:c,d,h,r,o
LONG=create-tree:delete-tree,help,reset-tree,override
OPTS=$(getopt -a --options $SHORT --longoptions $LONG -- "$@")

flavor="features"
is_existing_tree=0
is_override=0
xkb_tag=""

usage () {
          echo ""
          echo "Usage: $0 [-c|--create-tree] [-d|--delete-tree] [-r|--reset-tree]"
          echo ""
          echo "Options:"
          echo "  -c, --create-tree                   	Create kernel tree based on given option <base/features>"
          echo "  -d, --delete-tree    	      		Delete the tree"
          echo "  -r, --reset-tree    	      		Delete the existing tree and re-create it"
          echo "  -o, --override    	      		Overrides the existing tree"
          exit 1
}

apply_patches() {
	echo "Applying local patches"
	while read p; do
		case "$p" in \#*)
			if [ ! -z "$flavor" ]; then
				echo $p | tr -d "#" | (read name; echo "Applying $name patches..!" >&2)
				if [[ "$flavor" == "base" ]]; then
					echo "Only base patches will be  applied"
					flavor=""
				fi
				continue
			else
				break
			fi
			;;
		esac
		git am -q -s "$WORKING_DIR/$p"
		if [ $? -ne 0 ]; then
			echo "Failed to apply patch $p"
			exit 1;
		fi
	done <$WORKING_DIR/series

	git -C "$WORKING_DIR/kernel" tag "xe-$xkb_tag"
	echo "Tree created in the kernel folder, Now follow normal kernel build process"
	exit;
}

create_kernel_tree () {

	if [ ! -x "$wget" ]; then
		echo "ERROR: wget not found." >&2
		exit 1
	elif [ ! -x "$tar" ]; then
		echo "ERROR: tar not found" >&2
		exit 1
	fi

	#check if tree is already created
	if [ -d "kernel" ]; then
		echo "Tree already exist"
		# if tree already exists, check whether the override option is provided or not
		# if yes, remove the kernel folder and create it freshly.
		# Otherwise store the current branch before creating the new one.
		if [ $is_override -gt 0 ]; then
			echo "Override option has provided hence deleting the tree"
			rm -rf kernel
		else
			echo "No override option provided hence creating the tree in same folder"
			echo "Storing the current tree to bkp_tree_$TIME_STAMP";
			git -C "$WORKING_DIR/kernel" branch "bkp_tree_$TIME_STAMP"
			base_sha=$(git -C "$WORKING_DIR/kernel" log --pretty=format:"%h" --reverse | head -1 2>&1)
			git -C "$WORKING_DIR/kernel" reset --hard $base_sha
			is_existing_tree=1
		fi
	fi

	# wget to download tarball
	if [ -f  "$KERNEL.tar.gz" ]; then
		echo "Using already downloaded $KERNEL.tar.gz" >&2
	elif ! $wget "$KERNEL_BASE$KERNEL.tar.gz" ; then
		echo "ERROR: can't find source" >&2
		exit 1
	fi

	if [ $is_existing_tree -gt 0 ]; then
		tar zxf "$WORKING_DIR/$KERNEL.tar.gz" -C "$WORKING_DIR/kernel" --strip-components=1
		cd "$WORKING_DIR/kernel"

	else
		tar zxf "$WORKING_DIR/$KERNEL.tar.gz"
		mv "$WORKING_DIR/$KERNEL" "$WORKING_DIR/kernel"
		cd "$WORKING_DIR/kernel"

		echo  "Initialising git and adding downloaded kernel"

		git init -q
		git commit --allow-empty -m "Empty commit"
	fi

	git add  *
	git commit -s -q -m "base $KERNEL"

	echo "$flavor backport"
	apply_patches
}

delete_kernel_tree () {
	if [ -d "kernel" ]; then
		rm -rf kernel
	fi
	if [ -f "$KERNEL.tar.gz" ]; then
		rm -rf "$KERNEL.tar.gz"
	fi
}

xkb_tag=$(git -C $WORKING_DIR describe --always --tags)
if [ ! $# -gt 0 ]; then
	echo "No option provided, so proceeding with create-tree"
        create_kernel_tree
fi

while [ $# -gt 0 ]; do
	for arg in "$@"
	do
		if [ "$arg" == "--override" ] || [ "$arg" == "-o" ]; then
			is_override=1
		fi
	done

        case $1 in
                -c|--create-tree|-o|--override)
			if [ ! $# -gt 1 ]; then
				echo "No option provided for creating the tree"
			else
				flavor=$2
			fi
                        echo "Creating the tree with $flavor"
                        create_kernel_tree
                        exit;;
                -d|--delete-tree)
                        echo "Deleting the tree"
                        delete_kernel_tree
			exit;;
		-r|--reset-tree)
			echo "Deleting the existing tree and re-creating it"
			delete_kernel_tree
			create_kernel_tree
			exit;;
                -h|--help)
                        usage
                        ;;
                *)
                        echo "Invalid option: $1"
                        usage
        esac
done
