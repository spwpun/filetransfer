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
    Finds whether and which register is used to store a string address.

    :param addr: basic block address
    :param idx: statement idx of the statement referencing a string
    :param s: string referenced in the statement pointed by idx
    :return: the register name the string is assigned to
    """

    if not are_parameters_in_registers(p):
        raise Exception("Parameters are not in registers")

    block = p.factory.block(addr)
    stmt = block.vex.statements[idx]
    no = cfg.get_any_node(addr)

    # sometimes strings are reference indirectly through an address contained in the
    # text section
    endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
    s_addr_2 = None
    try:
        s_addr_2 = struct.unpack(endianess, ''.join(p.loader.memory.read_bytes(s_addr, p.arch.bytes)))[0]
    except:
        pass

    if hasattr(stmt, 'offset'):
        return p.arch.register_names[stmt.offset]

    # damn! The string is not assigned directly to a register, but to a tmp.
    # It means we have to find out what register is used to pass the string
    # to the function call
    # save the function manager, CFGAccurate will change it
    fm = p.kb.functions

    cfga = p.analyses.CFGAccurate(starts=(no.function_address,), keep_state=True, call_depth=0)
    no = cfga.get_any_node(addr)
    if not no:
        cfga = p.analyses.CFGAccurate(starts=(addr,), keep_state=True, call_depth=0)
        no = cfga.get_any_node(addr)
        if not no:
            return None

    args = get_args_call(p, no)

    # restore the old function manager
    p.kb.functions = fm

    for _, vals in args.iteritems():
        for o, v in vals:
            if v in (s_addr, s_addr_2):
                return p.arch.register_names[o]
    return None
        
def are_parameters_in_registers(p):
    return hasattr(p.arch, 'argument_registers')


    

if __name__  == '__main__':
    
    bin_path = '/home/angr/bgpd' 
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
    found = lambda *x:True
    for a,s in direct_str_refs:
        info_collected[s.address] = []
        
        if s.vex.jumpkind == 'Ijk_Call' or s.irsb.jumpkind == 'Ijk_Call':
            for (irsb_addr, stmt_idx, insn_addr) list(s.refs):
                if are_parameters_in_registers(p):
                    reg_used = get_reg_used(self._current_p, self._current_cfg, irsb_addr, stmt_idx, a, key_addrs)
                    if not reg_used:
                        continue
                    ret = found(cfg.get_any_node(irsb_addr), s.address, reg_used)

                    if ret is None:
                        continue
                    info_collected[s.address].append(ret)
                else:
                    log.error("_find_key_xref_in_call: arch doesn t use registers to set function parameters."
                              "Implement me!")
                    continue

                if only_one:
                    break
