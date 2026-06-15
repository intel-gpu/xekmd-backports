#!/bin/sh

KERNEL_HEADERS="/lib/modules/$(uname -r)/build/"
BACKPORT_DIR="."

helpFunction()
{
	echo ""
	echo "Usage: $0 -h headerspath -b backort_path"
	echo -e "\t-h <path to kernel headers>"
	echo -e "\t-b <path to backport release folder>"
	exit 1
}

while getopts "h:b:" opt
do
	case "$opt" in
		h ) KERNEL_HEADERS="$OPTARG" ;;
		b ) BACKPORT_DIR="$OPTARG" ;;
		? ) helpFunction ;; # Print helpFunction
	esac
done


BACKPORT_PATH="$BACKPORT_DIR/backport-include/backport/automacro.h"

#
# Start - Macro Verifications
#

# check if __assign_str prototype arguments
# Returns: 0 if only 1 argument, 1 if 2 arguments
BPM_MACRO_ASSIGN_STR_ARG2_PRESENT=`cat $KERNEL_HEADERS/include/trace/stages/stage6_event_callback.h | grep "define __assign_str(" | grep ',' | grep ')' | wc -l`


#
# End - Macro Verifications
#

## Pre Macro File Additions
(
echo "#ifndef _BACKPORTED_AUTO_MACRO_H"				;\
echo "#define _BACKPORTED_AUTO_MACRO_H"				;\
echo "/*"							;\
echo " * Automatically generated file, don't edit!"		;\
echo " * Changes will be overwritten"				;\
echo " */"							;\
echo ""								;\
) > $BACKPORT_PATH

## Add all the Macro's Extracted

if [ "$BPM_MACRO_ASSIGN_STR_ARG2_PRESENT" = "1" ]; then	\
echo "#define BPM_ASSIGN_STR_SECOND_ARG_PRESENT"		;\
fi >> $BACKPORT_PATH				;\

## Post Macro File Additions

(								\
echo ""								;\
echo "#endif /* _BACKPORTED_AUTO_MACRO_H */"			;\
) >> $BACKPORT_PATH					;\
