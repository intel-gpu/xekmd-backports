#!/bin/bash

KERNEL="linux-6.11-rc6"
# Linux
wget=/usr/bin/wget
tar=/bin/tar
WORKING_DIR="$PWD"

KERNEL_BASE="https://git.kernel.org/torvalds/t/"

SHORT=c,d,h,b:
LONG=create-tree,delete-tree,help,backport:
OPTS=$(getopt -a --options $SHORT --longoptions $LONG -- "$@")

flavor="base"

usage () {
          echo ""
          echo "Usage: $0 [-c|--create-tree] [-b | backport <base/features>] [-d|--delete-tree]"
          echo ""
          echo "Options:"
          echo "  -c, --create-tree                   	Creates the kernel tree and apply the backport patches"
          echo "  -b, --backport <base/features>      	backport options: default <base>"
          echo "  -d, --delete-tree    	      		Delete the tree"
          exit 1
}


create_kernel_tree () {

	if [ ! -x "$wget" ]; then
		echo "ERROR: wget not found." >&2
		exit 1
	elif [ ! -x "$tar" ]; then
		echo "ERROR: tar not found" >&2
		exit 1
	fi

	#check if tree is alreday created
	if [ -d "kernel" ]; then
		read -p "WARNING: Tree already exists, do you want to overwrite? (y/n) " yn
		case $yn in
			[yY] ) echo ok, we will proceed;
				rm -rf kernel;
				;;
			* ) echo exiting;
				exit;;
		esac
	fi


	# wget to download tarball
	if [ -f  "$KERNEL.tar.gz" ]; then
		echo "Using already downloaded $KERNEL.tar.gz" >&2
	elif ! $wget "$KERNEL_BASE$KERNEL.tar.gz" ; then
		echo "ERROR: can't find source" >&2
		exit 1
	fi


	tar zxf "$WORKING_DIR/$KERNEL.tar.gz"

	mv "$WORKING_DIR/$KERNEL" "$WORKING_DIR/kernel"

	cd "$WORKING_DIR/kernel"

	echo  "Initialising git and adding downloaded kernel"

	git init -q
	git add  *
	git commit -s -q -m "base $KERNEL"

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
		git am -q -s "$p"
		if [ $? -ne 0 ]; then
			echo "Failed to apply patch $p"
			exit 1;
		fi
	done <$WORKING_DIR/series

	echo "Tree created in the kernel folder, Now follow normal kernel build process"
}


delete_kernel_tree () {
	if [ -d "kernel" ]; then
		rm -rf kernel
	fi
	if [ -f "$KERNEL.tar.gz" ]; then
		rm -rf "$KERNEL.tar.gz"
	fi
	exit;
}

if [ ! $# -gt 0 ]; then
	echo "No option provided, so proceeding with create-tree"
        create_kernel_tree
fi

while [ $# -gt 0 ]; do
        case $1 in
                -c|--create-tree)
                        echo "Creating the tree"
                        create_kernel_tree
                        shift
                        ;;
                -d|--delete-tree)
                        echo "Deleting the tree"
                        delete_kernel_tree
                        shift
                        ;;
		-b|--backport)
			flavor="$2"
			echo "$2 backport"
			create_kernel_tree
			shift 2
			;;
                -h|--help)
                        usage
                        shift
                        ;;
                *)
                        echo "Invalid option: $1"
                        usage
        esac
done
