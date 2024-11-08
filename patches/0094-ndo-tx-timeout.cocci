@r@
identifier OPS;
identifier tx_timeout_fn;
fresh identifier tx_timeout_fn_wrap = "bp_" ## tx_timeout_fn;
position p;
@@
struct net_device_ops OPS@p = {
+#if LINUX_VERSION_IS_GEQ(5,6,0)
	.ndo_tx_timeout = tx_timeout_fn,
+#else
+	.ndo_tx_timeout = tx_timeout_fn_wrap,
+#endif
};

@@
identifier r.tx_timeout_fn_wrap;
identifier r.tx_timeout_fn;
@@
void tx_timeout_fn(...) {...}
+#if LINUX_VERSION_IS_LESS(5,6,0)
+/* Just declare it here to keep sparse happy */
+void tx_timeout_fn_wrap(struct net_device *dev);
+void tx_timeout_fn_wrap(struct net_device *dev)
+{
+	tx_timeout_fn(dev, 0);
+}
+EXPORT_SYMBOL_GPL(tx_timeout_fn_wrap);
+#endif
