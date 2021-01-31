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
            if chr(c) in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                t_str += chr(c)
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

def get_args_call(p, no):
    """
    Gets the arguments of function call

    :param p: angr project
    :param no: CFG Accurate node of the call site
    :return: the values of function called in node no
    """

    ins_args = get_ord_arguments_call(p, no.addr)
    if not ins_args:
        ins_args = get_any_arguments_call(p, no.addr)

    vals = {}

    for state in no.final_states:
        vals[state] = []
        for ins_arg in ins_args:
            # get the values of the arguments
            if hasattr(ins_arg.data, 'tmp') and ins_arg.data.tmp in state.scratch.temps:
                val = state.scratch.temps[ins_arg.data.tmp]
                val = val.args[0] if type(val.args[0]) in (int, long) else None
                if val:
                    vals[state].append((ins_arg.offset, val))
            elif type(ins_arg.data) == pyvex.expr.Const and len(ins_arg.data.constants) == 1:
                    vals[state].append((ins_arg.offset, ins_arg.data.constants[0].value))
            else:
                print("Cant' get the value for function call")
    return vals

def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_argument_regs[p.arch.name]:
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and s.offset == reg_off]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params

def get_any_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call.

    :param p: angr project
    :param b_addr: basic block address
    :return: instructions setting arguments
    """

    set_params = []
    b = p.factory.block(b_addr)
    put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put']
    for stmt in put_stmts:
        if stmt.offset in ordered_argument_regs[p.arch.name]:
            set_params.append(stmt)

    return set_params  

if __name__  == '__main__':
    
    bin_path = '/home/karonte/karonte/firmware/test/bgpd' 
    search_str = 'mac'
    info_collected = {}

    p = angr.Project(bin_path)
    b = p.loader.main_object.binary
    res = get_bin_strings(b)
    offs = [x[1] for x in res if search_str in x[0] ]
    refs = [p.loader.main_object.min_addr + off for off in offs ]
    print ("*mac* strs addrs:", [hex(ref) for ref in refs] )
    
    cfg = p.analyses.CFGFast(collect_data_references=True,
                            extra_cross_references=True)
    direct_str_refs = [s for s in cfg.memory_data.items() if s[0] in refs]
    found = lambda *x:True
    for a,s in direct_str_refs:
        info_collected[s.address] = []
        
        if s.vex.jumpkind == 'Ijk_Call' or s.irsb.jumpkind == 'Ijk_Call':
            for (irsb_addr, stmt_idx, insn_addr) in list(s.refs):
                if are_parameters_in_registers(p):
                    reg_used = get_reg_used(p, cfg, irsb_addr, stmt_idx, a, key_addrs)
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
    print(info_collected)
