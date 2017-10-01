#ifdef CONFIG_PLUGINS
DEF_HELPER_FLAGS_2(plugin_insn_cb, TCG_CALL_NO_RWG, void, env, ptr)
DEF_HELPER_FLAGS_1(plugin_tb_pre_cb, TCG_CALL_NO_RWG, void, env)
#endif
