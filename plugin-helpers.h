#ifdef CONFIG_PLUGINS
DEF_HELPER_FLAGS_2(plugin_insn_cb, TCG_CALL_NO_RWG, void, env, ptr)
DEF_HELPER_FLAGS_2(plugin_tb_exec_cb, TCG_CALL_NO_RWG, void, env, ptr)
#endif
