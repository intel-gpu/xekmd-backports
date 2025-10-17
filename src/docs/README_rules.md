## Adding Autotools M4 Files

In order to add a new M4 Functions please follow below rules
1) Create File under autotools/m4/ folder with ".m4" extension.
2) Naming of file should reflect functional area.,
   For example, all controlled functions related to dma_fence_array are added into dma_fence_array.m4 file
3) Use comments with "dnl #" prefix
4) Add Reference commit details and Commit Header in format above function definition
   Example:
   dnl #
   dnl # v6.11-rc2-ddc94d0b17e8e
   dnl # dma-buf: Split out dma fence array create into alloc and arm functions
   dnl #
5) Add all macros with BPM_ prefix(Example: BPM_DMA_FENCE_ARRAY_ALLOC_NOT_PRESENT)
6) Function name should be added into main file function "AC_XE_CONFIG" inside the file autotools/m4/xe.m4
7) Important: Always add function name above "AC_KERNEL_WAIT".
