import angr
import string
import monkeyhex

# Strings Buff
MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_ ' 
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=-_)(*&^$#@!~`|<>{}[]"
SEPARATOR_CHARS = ('-', '_')


def get_bin_strings(filename):
    # Retrive the strings within a binary
    with open(filename, 'rb') as f:
        res = []
        last_off = None
        off = 0
        t_str = "" #terminate char
        
        for c in f.read():
            if c in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                t_str += c
            else:
                if t_str and len(t_str) > 1:
                    res.append((t_str, last_off)) # save the strings and their offsets
                last_off = None
                t_str = ""
            off += 1
    
    return res

def get_mem_string(mem_bytes, extended = True):
    # Return the set of consecutive ASCII chars within a list of bytes
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS
    
    for c in mem_bytes:
        if c not in chars:
            break
        tmp += c
    
    return tmp

def get_string(p, mem_addr, extended=False):
    """
    Get a string from a memory address

    :param p: angr project
    :param mem_addr: memory address
    :param extended: use extended set of characters
    :return: the string
    """

    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)
    if mem_addr<bin_bounds[0] and mem_addr>bin_bounds[1]:
        return '[Error] mem_addr invalid!'
    try:
        text_bounds = (p.loader.main_object.sections_map['.text'].min_addr,
                       p.loader.main_object.sections_map['.text'].max_addr)
    except:
        text_bounds = None

    # check if the address contain another address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
    except:
        tmp_addr = None

    # if the .text exists, we make sure that the actual string
    # is someplace else.
    if text_bounds is not None and text_bounds[0] <= mem_addr <= text_bounds[1]:
        # if the indirect address is not an address, or it points to the text segment,
        # or outside the scope of the binary
        if not tmp_addr or text_bounds[0] <= tmp_addr <= text_bounds[1] or \
               tmp_addr < bin_bounds[0] or tmp_addr > bin_bounds[1]:
            return ''

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    try:
        if tmp_addr and bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        string_2 = ''

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''

def find_functions(p, cfg, str_info, key_str, func_indexes, cnter):
    '''
    cnter is a counter to calc the times of function
    '''
    offs = [x[1] for x in str_info if key_str in x[0]]
    key_addrs = [p.loader.main_object.min_addr + off for off in offs] # Maybe here are some mistakes
    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)
    
    for func in func_indexes:
        c_func = cfg.kb.functions[func[0]]
        for bb in c_func.blocks:
            if bb.addr == 0x5020740:
                #DEBUG                
                print "[DEBUG]", c_func.name,"occurred 0x5020740 constants, then find it in IDA"
                #DEBUG
            if bb.addr > bin_bounds[1] or bb.addr < bin_bounds[0]:
                continue
            for con in bb.vex.all_constants:
                if con.value in key_addrs:
                    try:
                        key = get_string(p, con.value, extended=True)
                    except:
                        key = '[Unfounded!]'
                    #print "[INFO] ",c_func.name,"called string: \"",key,"\" and it's at ",hex(con.value)
                    cnter[c_func.name] = 1 if not cnter.has_key(c_func.name) else cnter[c_func.name]+1
        
def data_save(filename, data):
    f = open(filename, 'a')
    statics = "--------There are "+str(len(data))+" functions.--------\nTimes     Function_name\n"
    f.write(statics)
    for i in range(len(data)):
        s = str(data[i][1]) + "    "+ data[i][0]+'\n'
        f.write(s)
    f.close()


def main():
    bin_path = '/home/karonte/karonte/firmware/test/bgpd'
    p = angr.Project(bin_path)
    cfg = p.analyses.CFG(collect_data_references=True, extra_cross_references=True)
    func_indexes = cfg.kb.functions.items()
    packet_strs = ['holdtime', 'Marker', 'AS', 'BGP Identifier', 'withdraw routes', 'Path attributes', 'OPEN', 'UPDATE', 'KEEPALIVE', 'NOTIFICATION']
    sm_strs = ['Idle', 'connect', 'active', 'opensent', 'openconfirm', 'established']
    str_info = get_bin_strings(bin_path)
    packet_cnter = {}
    sm_cnter = {}
    for key_str in packet_strs:
        find_functions(p, cfg, str_info, key_str, func_indexes, packet_cnter)
    for key_str in sm_strs:
        find_functions(p, cfg, str_info, key_str, func_indexes, sm_cnter)
    order_p_cnter = sorted(packet_cnter.items(), key = lambda x:x[1], reverse = True)
    order_s_cnter = sorted(sm_cnter.items(), key = lambda x:x[1], reverse = True)
    print "The most 5 high frequency packet functions: ", order_p_cnter[:5]
    print "The most 5 high frequency state_ functions: ", order_s_cnter[:5]
    
    data_save('packet_fucntions_data', order_p_cnter)
    data_save('statemch_functions_data', order_s_cnter)


if __name__ == "__main__":
    main()
