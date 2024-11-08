@r@
identifier s,expr;
@@

struct ethtool_ops s = {
+#if LINUX_VERSION_IS_GEQ(5,7,0)
	.supported_coalesce_params = expr,
+#endif
};
