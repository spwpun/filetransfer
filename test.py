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

def main():
    bin_path = '/home/karonte/karonte/firmware/test/bgpd'
    p = angr.Project(bin_path)
    cfg = p.analyses.CFG(collect_data_references=True, extra_cross_references=True)
    func_indexes = cfg.kb.functions.items()
    packet_strs = ['holdtime', 'Marker', 'AS', 'BGP Identifier', 'withdraw routes', 'Path attributes', 'OPEN', 'UPDATE', 'KEEPALIVE', 'NOTIFICATION']
    sm_strs = ['Idle', 'connect', 'active', 'opensent', 'openconfirm', 'established']
    str_info = get_bin_strings(bin_path)
    offs = [x[1] for x in str_info if 'mac' in x[0]] # Just test for one string
    key_addrs = [p.loader.main_object.min_addr + off for off in offs]

    for func in func_indexes:
        c_func = cfg.kb.functions[func[0]]
        for bb in c_func.blocks:
            for con in bb.vex.all_constants:
                if con.value in key_addrs:
                    key = get_string(p,con.value, extended=True)
                    print c_func.name,"called string: \"",key,"\" and it's at ",hex(con.value)
if __name__ == "__main__":
    main()
