#combine_block.py
import keypatch
from idaapi import *
import capstone
import struct



start_addr=0x48D000 #起始地址
end_addr=0x48D8DA #结束地址

codes=get_bytes(start_addr,get_item_size(end_addr)+end_addr-start_addr)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)

nop_code=0x90
for i in range(end_addr-start_addr):
    idc.patch_byte(start_addr+i,nop_code)

wirte_offect=0
fun_offset=start_addr
for code in md.disasm(codes,start_addr):
    if code.mnemonic=='nop': #排除这些指令
        continue
    block_bytes=bytes(code.bytes)
    if code.mnemonic=='call':
        if code.op_str.startswith('0x'):
            called_addr=int(code.op_str,16)
            fix_addr=called_addr-fun_offset-wirte_offect-5
            fix_bytes=struct.pack('i',fix_addr)
            block_bytes=bytes(code.bytes[0:1])+fix_bytes
    patch_bytes(start_addr+wirte_offect,block_bytes)
    wirte_offect=wirte_offect+len(block_bytes)



