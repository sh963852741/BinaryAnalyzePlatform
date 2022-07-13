/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author:Lei Cui
 * @date Jan 24 2021
 */

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "hookapi.h"
#include "DECAF_callback.h"

#include "utils/Output.h"
#include "function_map.h"
#include "vmi_callback.h"
#include "vmi_c_wrapper.h"

// Added by Lei
// extern void DECAF_log_info(char * info);

//basic stub for plugins
static plugin_interface_t track_proc_interface;

DECAF_Handle handle_block_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_start_cb = DECAF_NULL_HANDLE; // added by Lei
DECAF_Handle handle_load_module_cb = DECAF_NULL_HANDLE;
FILE * track_proc_log=DECAF_NULL_HANDLE;


#define FUNC_BLK_CNT 4096
#define NAME_LEN 512
char modname_t[NAME_LEN];
char func_name_t[NAME_LEN];

#if 0
#define MAX_STACK_SIZE 5000
uint32_t sys_call_ret_stack[MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[MAX_STACK_SIZE];
uint32_t cr3_stack[MAX_STACK_SIZE];
uint32_t stack_top = 0;
#endif

struct func_block
{
	char mod_name[NAME_LEN];
	char func_name[NAME_LEN];
	target_ulong base_addr;
	target_ulong func_addr;
	target_ulong func_end_addr;
	int size;
};

// TODO: need an efficient indexing (pc as key) method
struct func_block func_blks[FUNC_BLK_CNT];
static int func_blk_cnt;

static int get_func_name_by_blk(target_ulong pc, char * mod_name, char*func_name)
{
    int i = 0;
    for(i = 0; i < func_blk_cnt; i++)
    {
        if(pc >= func_blks[i].func_addr && pc <= func_blks[i].func_end_addr)
        {
            strcpy(mod_name, func_blks[i].mod_name);
            strcpy(func_name, func_blks[i].func_name);
            return 0;
        }
    } 
    return -1;
}


static bool export_symbols_loaded = false;

static target_ulong expected_cr3  = 0 ;
static char * expected_proc_name = DECAF_NULL_HANDLE; // i.e., expected_mod_name
static target_ulong expected_pc_start = 0;
static target_ulong expected_pc_end = 0;

static int load_export_symbols(const char *expected_mod_name)
{
    FILE * fp;
    fp = fopen("exported_symbols.log", "r");
    if(fp == NULL)
	return -1;
    char mod_name[NAME_LEN];
    char func_name[NAME_LEN];
    uint64_t base_addr; // Elf64_Addr
    uint64_t func_addr; // Elf64_Addr
    int size;

    int ret = 0;
    bool found_mod = false;
    while(!feof(fp)){
        ret = fscanf(fp, "mod_name=%s elf_name=%s base_addr=%x func_addr=%x, size=%d \n",mod_name, func_name, &base_addr, &func_addr, &size);
        if(ret < 0){
	    //printf("ret is %d \n", ret);
            goto over;
	}
        //printf("mod_name=\"%s\" elf_name=\"%s\" base_addr=\"%x\" func_addr= \"%lu\", size= \"%d\" \n",mod_name, func_name, base_addr, (unsigned long)func_addr, size);    

        if(strcmp(mod_name, expected_mod_name) == 0) // expected mod
        {
		strcpy(func_blks[func_blk_cnt].mod_name, mod_name);
		strcpy(func_blks[func_blk_cnt].func_name, func_name);
		func_blks[func_blk_cnt].base_addr = base_addr;
		func_blks[func_blk_cnt].func_addr = func_addr;
		func_blks[func_blk_cnt].size = size;
		func_blks[func_blk_cnt].func_end_addr = func_addr + size;
		func_blk_cnt++;
		found_mod = true;
        	export_symbols_loaded = true;
        }
	// NOTE: when func_addr and size is 0, it is an lib function
    }
    //printf("load export symbols over \n");

over:
    fclose(fp);
    if(!found_mod)
	return -1;
    return 0;
}


void do_block_start_cb(DECAF_Callback_Params *param)
{
	char mod_name[NAME_LEN];
	char func_name[NAME_LEN];
	CPUState * env=param->be.env;
	target_ulong cr3 = DECAF_getPGD(env);

	//printf("track_proc.c block_start \n");
        int get_func_fast = -1;

	// only consider user-space applications
	// TODO: may ignore some operations, e.g., syscall?
	if((unsigned long)param->bb.tb->pc > 2000000000)
		return;

        if(!export_symbols_loaded)
	{
            int ret = load_export_symbols(expected_proc_name);
            if(ret == -1) 
	    {
		// exported_symbols file is missing, so force to call VMI_extract_symbols() which generates exported_symbols
		//printf("load_export_symbols fail \n");
    	        funcmap_get_name_c(param->bb.tb->pc, cr3, &mod_name, &func_name);
                memset(mod_name, 0x00, sizeof(char)*NAME_LEN);
                memset(func_name, 0x00, sizeof(char)*NAME_LEN);
	    }
	    else
		printf("load_export_symbols success \n");
        }

        if(expected_cr3 && (cr3 == expected_cr3))
  	{
            if(export_symbols_loaded)
            {
	        // read from exported symbols directly
                get_func_fast = get_func_name_by_blk(param->bb.tb->pc, &mod_name, &func_name);
                if(get_func_fast == 0)
                {
		    //printf("---- get fast, mod: %s, func: %s, pc: %lu, cr3: %lu \n", mod_name, func_name, (unsigned long)param->bb.tb->pc, (unsigned long)env->cr[3]);
		    //fflush(stdout);
		    fprintf(track_proc_log, "FAST, mod: %s, func: %s, pc: %lu, cr3: %lu \n", mod_name, func_name, (unsigned long)param->bb.tb->pc, (unsigned long)env->cr[3]);
		    fflush(track_proc_log);
                    return ;
                }
		else
		{ 
                    ;//printf("get func fast fail ------------ \n");
		}
            }
	    else
		printf("emport symbols is not loaded \n");
 	}

	if (0 == funcmap_get_name_c(param->bb.tb->pc, cr3, &mod_name, &func_name))
	{
	    //printf("---- START: %s %s \n", mod_name, func_name);
	    if(strcmp(mod_name, expected_proc_name) == 0)
	    {
	        printf("---- START: %s %s \n", mod_name, func_name);
		expected_cr3 = cr3;
		set_expected_cr3(cr3);
		if(0 == funcmap_get_pc_range(param->bb.tb->pc, cr3, &expected_pc_start, &expected_pc_end))
                    set_expected_pc_range(expected_pc_start, expected_pc_end); // set the start/end address of vma of mod
	    }
	    if(strcmp(mod_name, expected_proc_name) == 0) // NOTE: handle multiple procs.   || strcmp(mod_name, "helloworld") == 0)
	    {
		//printf("---- START, mod: %s, func: %s, size: %d, icount: %u, pc: %lu, csbase: %x, cr3: %lu \n", mod_name, func_name, param->bb.tb->size, param->bb.tb->icount, (unsigned long)param->bb.tb->pc, param->bb.tb->cs_base, (unsigned long)env->cr[3]);
		//fflush(stdout);
		fprintf(track_proc_log, "SLOW, mod: %s, func: %s, pc: %lu, cr3: %lu \n", mod_name, func_name, (unsigned long)param->bb.tb->pc, (unsigned long)env->cr[3]);
		fflush(track_proc_log);
	    }
	}
	else
	{
	    if(cr3 == expected_cr3) 
                ;
	        //printf("get no func, %x \n ", (unsigned long)param->bb.tb->pc);
	}
}


void load_module_notify(VMI_Callback_Params * params)
{
	// TODO: set cr3, pc_start and pc_end here!!
        char * mod_name = params->lm.name;
	int mod_size = params->lm.size;
	char * mod_full_name = params->lm.full_name;
        target_ulong cr3 = params->lm.cr3;
        if(strcmp(mod_name, expected_proc_name) == 0)
	    printf("************* load the expected module \n");
}


void track_proc_cleanup()
{
	if(track_proc_log)
	{
		fclose(track_proc_log);
		track_proc_log = NULL;
	}
	//if(handle_block_end_cb)
	//	DECAF_unregisterOptimizedBlockEndCallback(handle_block_end_cb);
	if(handle_block_start_cb)
		DECAF_unregisterOptimizedBlockBeginCallback(handle_block_start_cb);
	if(handle_load_module_cb)
		VMI_unregister_callback(VMI_LOADMODULE_CB, handle_load_module_cb);
 
	//handle_block_end_cb = DECAF_NULL_HANDLE;
	handle_block_start_cb = DECAF_NULL_HANDLE; // added by Lei
	handle_load_module_cb = DECAF_NULL_HANDLE;
	
	// reset local
	export_symbols_loaded = false;
	memset(func_blks, 0x00, FUNC_BLK_CNT*sizeof(struct func_block));
        if(expected_proc_name)
            expected_proc_name = DECAF_NULL_HANDLE; // i.e., expected_mod_name
	expected_pc_start = 0;
	expected_pc_end = 0;
        expected_cr3 = 0;

	// reset global
	set_expected_cr3(0);
	set_expected_pc_range(0, 0);
        set_tcg_log_file(false);// operated upon unload
        printf("cleanup, set_expeced_mod_name start\n");
	set_expected_mod_name(""); //TODO NULL or ""?
}

void do_enable_track_proc_check( Monitor *mon, const QDict *qdict)
{
	const char *tracefile_t = qdict_get_str(qdict, "tracefile");
	char *application_name = qdict_get_str(qdict, "application"); // Added by Lei
	//strcpy(expected_proc_name, application_name); // Added by Lei, get expected proc name for dumping
        expected_proc_name = (char*)malloc(NAME_LEN);
	strcpy(expected_proc_name, application_name); // Added by Lei, get expected proc name for dumping
	set_expected_mod_name(expected_proc_name); //set expected name to be tracked
        printf("application name is %s \n", expected_proc_name);
	track_proc_log = fopen(tracefile_t,"w+");
	if(!track_proc_log)
	{
		DECAF_printf("the %s can not be open or created !!",tracefile_t);
		return;
	}
	// do_block_end_cb is commented by Lei
	//fprintf(track_proc_log,"Process Read(0)/Write(1) vaddOfTaintedMem   paddrOfTaintedMem    Size   "
	//		"TaintInfo   CurEIP \t ModuleName   \t CallerModuleName \t CallerSystemCall\n");
	//if(!handle_block_end_cb)
	//	handle_block_end_cb =  DECAF_registerOptimizedBlockEndCallback(
	//			do_block_end_cb, NULL, INV_ADDR, INV_ADDR);
	if(!handle_block_start_cb)
		handle_block_start_cb =  DECAF_registerOptimizedBlockBeginCallback(
				do_block_start_cb, NULL, INV_ADDR, OCB_ALL);
	if(!handle_load_module_cb)
		handle_load_module_cb = VMI_register_callback(VMI_LOADMODULE_CB, load_module_notify, NULL);

        set_tcg_log_file(true); // start logging
	printf("track_proc.c Enable over\n");
	// NOTE: we only track the mod of process itself, i.e., the text segment
}


void do_disable_track_proc_check( Monitor *mon, const QDict *qdict)
{
	track_proc_cleanup();
	DECAF_printf("disable track_proc successfully \n");
}

static mon_cmd_t track_proc_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	track_proc_interface.mon_cmds = track_proc_term_cmds;
	track_proc_interface.plugin_cleanup = &track_proc_cleanup;

	//initialize the plugin
	return (&track_proc_interface);
}


#if 0
void do_block_end_cb(DECAF_Callback_Params *param)
{
	unsigned char insn_buf[2];
	int is_call = 0, is_ret = 0;
	int b;
	DECAF_read_mem(param->be.env,param->be.cur_pc,sizeof(char)*2,insn_buf);

	switch(insn_buf[0]) {
		case 0x9a:
		case 0xe8:
		is_call = 1;
		break;
		case 0xff:
		b = (insn_buf[1]>>3) & 7;
		if(b==2 || b==3)
		is_call = 1;
		break;

		case 0xc2:
		case 0xc3:
		case 0xca:
		case 0xcb:
		is_ret = 1;
		break;
		default: break;
	}


	// added by Lei
	char mod_name[512];
	char func_name[512];
	CPUState * env=param->be.env;

	target_ulong cr3 = DECAF_getPGD(env);
	if (0 == funcmap_get_name_c(param->bb.tb->pc, cr3, &mod_name, &func_name))
	{
		//if(strcmp(mod_name, "user32.dll") == 0 && strcmp(func_name, "GetPropW") == 0)
		// if(strcmp(mod_name, "user32.dll") == 0)
		#if 0
		{
			//printf("---- END: %s %s \n", mod_name, func_name);
			//printf("---- END: bb: size, %d, icount, %u \n ", param->bb.tb->size, param->bb.tb->icount);
			char info[512];
			memset(info, 0x00, 512);
			sprintf(info, "---- END, mod: %s, func: %s, size: %d, icount: %u \n\n\n", mod_name, func_name, param->bb.tb->size, param->bb.tb->icount);
			if(strcmp(mod_name, "hello") == 0)
				DECAF_log_info(info);
		}
		#endif
	}
	else
	{
		;//DECAF_log_info("---- END, no func name is got \n\n\n");
	}
	/*
	 * Handle both the call and the return
	 */
	if (is_call)
	check_call(param);
	else if (is_ret)
	check_ret(param);
}
#endif


#if 0
void do_read_taint_mem(DECAF_Callback_Params *param)
{
	uint32_t eip=DECAF_getPC(cpu_single_env);
	uint32_t cr3= DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
	if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
	{
		strcpy(name, "<None>");
		bzero(&dm, sizeof(dm));
	}
	if(stack_top)
	{
		if(cr3 == cr3_stack[stack_top-1])
			funcmap_get_name_c(sys_call_entry_stack[stack_top-1], cr3, modname_t, func_name_t);
	}
}
#endif

#if 0
void do_write_taint_mem(DECAF_Callback_Params *param)
{
	uint32_t eip= DECAF_getPC(cpu_single_env);
	uint32_t cr3= DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t  dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
	if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
	{
		bzero(&dm, sizeof(dm));
	}

	if(stack_top)
	{
		if(cr3 == cr3_stack[stack_top-1])
			funcmap_get_name_c(sys_call_entry_stack[stack_top-1], cr3, modname_t, func_name_t);
	}
}
#endif

#if 0
void check_call(DECAF_Callback_Params *param)
{
	CPUState *env=param->be.env;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;

	if(stack_top == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack,&sys_call_ret_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack,&sys_call_entry_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}
	if(funcmap_get_name_c(pc, cr3, modname_t, func_name_t))
	{
		DECAF_read_mem(env,env->regs[R_ESP],4,&sys_call_ret_stack[stack_top]);
		sys_call_entry_stack[stack_top] = pc;
		cr3_stack[stack_top] = cr3;
		stack_top++;
	}
}

void check_ret(DECAF_Callback_Params *param)
{
	if(!stack_top)
		return;
	if(param->be.next_pc == sys_call_ret_stack[stack_top-1])
	{
		stack_top--;
	}
}
#endif
