#!/usr/bin/env python3

import angr
import string

def get_bin_strings(filename):
    """
    Retrive the strings within a binary
    """
    with open(filename, "rb") as f:
        results = []
        last_off = None
        off = 0
        t_str = "" #terminate char

        for c in f.read():
            if c in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                t_str += c
            else:
                if t_str and len(t_str) > 1:
                    results.append((t_str, last_off))
                last_off = None
                t_str = ""
            off += 1

    return results

def get_reg_used(p, cfg, addr, idx, s_addr):
    """
    Finds whether and which register is used to store a string address
    """
    if not hasattr(p.arch, 'argument_registers'):
        raise Exception("Parameters are not in reegisters!")
    

if __name__  == '__main__':
    
    bin_path = '/home/karonte/karonte/firmware/test/bgpd' 
    search_str = 'holdtime'
    info_collected = {}

    p = angr.Project(bin_path)
    b = p.loader.main_object.binary
    res = get_bin_strings(b)
    offs = [x[1] for x in res if search_str in x[0] ]
    refs = [p.loader.main_object.min_addr + off for off in offs ]
    print "*holdtime* strs addrs:", [hex(ref) for ref in refs] 
    
    cfg = p.analyses.CFG(collect_data_references=True,
                            extra_cross_references=True)
    direct_str_refs = [s for s in cfg.memory_data.items() if s[0] in refs]
    for a,s in direct_str_refs:
        info_collected[s.address] = []
        
        if s.vex.jumpkind == 'Ijk_Call' or s.irsb.jumpkind == 'Ijk_Call':
            for (irsb_addr, stmt_idx, insn_addr) list(s.refs):
                print
