
{
		.name = "enable_track_proc_check",
		.args_type = "tracefile:F,application:s",
		.mhandler.cmd = do_enable_track_proc_check,
		.params = "trace_file name application name",
		.help = "check every tainted instruction to see what module/function it belongs to "
},
{
		.name = "disable_track_proc_check",
		.args_type = "",
		.mhandler.cmd = do_disable_track_proc_check,
		.params = "no params",
		.help = "disable function that check every tainted instruction to see what module/function it belongs to "
},
