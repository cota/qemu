#ifdef CONFIG_PLUGINS
DEF_HELPER_FLAGS_2(plugin_dyn_cb_no_rwg, TCG_CALL_NO_RWG, void, env, ptr)
DEF_HELPER_FLAGS_2(plugin_dyn_cb_no_wg, TCG_CALL_NO_WG, void, env, ptr)
DEF_HELPER_FLAGS_3(plugin_mem_exec_cb, TCG_CALL_NO_RWG, void, env, tl, i32)
#endif
