@r1@
identifier drv, fn;
@@
static struct pci_driver drv = {
	.driver = {
+#if LINUX_VERSION_IS_GEQ(4,17,0)
		.coredump = fn,
+#endif
		...
	},
	...
};

@r11 depends on r1@
identifier r1.fn;
@@
+#if LINUX_VERSION_IS_GEQ(4,17,0)
fn(...)
{
	...
}
+#endif


@r2@
identifier drv, fn;
@@
 static struct pci_driver drv = {
+#if LINUX_VERSION_IS_GEQ(4,17,0)
	.driver.coredump = fn,
+#endif
	...
 };

@r21 depends on r2@
identifier r2.fn;
@@
+#if LINUX_VERSION_IS_GEQ(4,17,0)
fn(...)
{
	...
}
+#endif


@r3@
identifier drv, fn;
@@
static struct usb_driver drv = {
	.drvwrap.driver = {
+#if LINUX_VERSION_IS_GEQ(4,17,0)
		.coredump = fn,
+#endif
		...
	},
	...
};


@r31 depends on r3@
identifier r3.fn;
@@
+#if LINUX_VERSION_IS_GEQ(4,17,0)
fn(...)
{
	...
}
+#endif


@r4@
identifier driver, fn;
@@
 static struct sdio_driver driver = {
	.drv = {
+#if LINUX_VERSION_IS_GEQ(4,17,0)
		.coredump = fn,
+#endif
		...
	},
	...
};


@r41 depends on r4@
identifier r4.fn;
@@
+#if LINUX_VERSION_IS_GEQ(4,17,0)
fn(...)
{
	...
}
+#endif
