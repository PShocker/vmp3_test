#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
#
#---------------------------------------------------------------------
import idc
from idaapi import *
import binascii
import struct

from capstone import *
md=Cs(CS_ARCH_X86,CS_MODE_32)

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """
    
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        self.asmfile=open('dump.asm','wb') #保存记录指令的文件
        self.record_count=0
 
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        if not self.asmfile ==None:
            self.asmfile.close()
 
    # def dbg_library_unload(self, pid, tid, ea, info):
    #     print("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
    #     return 0
 
    # def dbg_process_attach(self, pid, tid, ea, name, base, size):
    #     print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
 
    # def dbg_process_detach(self, pid, tid, ea):
    #     print("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
    #     return 0
 
    # def dbg_library_load(self, pid, tid, ea, name, base, size):
    #     print ("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))
 
    def dbg_bpt(self, tid, ea):
        print("0x%x     %s" % (ea, GetDisasm(ea)))
        codelen=get_item_size(ea)
        self.record_count=self.record_count+codelen
        b=get_bytes(ea,codelen)
        self.asmfile.write(b)
        self.asmfile.flush()
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0
 
    # def dbg_suspend_process(self):
    #     print ("Process suspended")
 
    # def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
    #     print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
    #         pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
    #     # return values:
    #     #   -1 - to display an exception warning dialog
    #     #        if the process is suspended.
    #     #   0  - to never display an exception warning dialog.
    #     #   1  - to always display an exception warning dialog.
    #     return 0
 
    def dbg_trace(self, tid, ea):
        print("0x%x     %s" % (ea, GetDisasm(ea)))
        if idc.print_insn_mnem(ea).startswith('j'): #不记录所有的跳转指令
            return 0
        
        if idc.print_insn_mnem(ea) == 'retn':#把retn 替换为lea esp,[esp+4]
            code=b'\x8D\x64\x24\x04' #lea esp,[esp+4]
            self.asmfile.write(code)
            self.asmfile.flush()
            self.record_count=self.record_count+len(code)
            return 0 
        if idc.print_insn_mnem(ea) == 'call':#把call 替换为call +5
            fix_addr=0
            mnemonic=struct.pack('B',idc.get_wide_byte(ea))
            op=struct.pack('i',fix_addr)
            call_asm=mnemonic+op
            self.asmfile.write(call_asm)
            self.asmfile.flush()
            self.record_count=self.record_count+get_item_size(ea)
            return 0 
        for addr in range(ea,idc.next_head(ea)):
            b=struct.pack('B',idc.get_wide_byte(addr))
            self.asmfile.write(b)
            self.asmfile.flush()
        self.record_count=self.record_count+get_item_size(ea)
        
        # eip = get_reg_value("EIP")
        # print("0x%x %s" % (eip, GetDisasm(eip)))
        # print("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        return 0
 
    # def dbg_step_into(self):
    #     eip = get_reg_value("EIP")
    #     print("0x%x %s" % (eip, GetDisasm(eip)))
 
    # def dbg_run_to(self, pid, tid=0, ea=0):
    #     print ("Runto: tid=%d" % tid)
    #     idaapi.continue_process()
 
 
    # def dbg_step_over(self):
    #     eip = get_reg_value("EIP")
    #     print("0x%x %s" % (eip, GetDisasm(eip)))
    #     self.steps += 1
    #     if self.steps >= 5:
    #         request_exit_process()
    #     else:
    #         request_step_over()
 
 
# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass
 
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
 
# Stop at the entry point
ep = get_inf_attr(INF_START_IP)
request_run_to(ep)
 
# Step one instruction
request_step_over()
 
# Start debugging
run_requests()