import angr
import string

def get_():
    pass

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
    p = angr.Project('./bgpd')
    cfg = p.analyses.CFG(collect_data_references=True, extra_cross_references=True)
    funcs = cfg.kb.functions
    print(func.name for func in funcs)

if __name__ == "__main__":
    main()
