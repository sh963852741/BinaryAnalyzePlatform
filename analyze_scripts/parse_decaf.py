import os

def parse_line(line):
    if line[0] != '-':
        return None, None
    if line.find('START') < 0:
        return None, None
    if line.find('mod') < 0:
        return None, None

    #print(line)
    items = line.split()
    func_name = items[5][:-1]
    pc_addr = items[7][:-1]

    return func_name, pc_addr


def parse_log(log_name):
    lines = None
    #with open(log_name, 'r') as fd:
    #    lines = fd.readlines()
    #for line in lines:

    func_dict = {}
    fd = open(log_name, 'r')
    while True:
        line = fd.readline()
        if line == '':
            break
        if line.strip() == "":
            continue
        func, pc = parse_line(line)
        if func is None:
            continue

        if func not in func_dict.keys():
            func_dict[func] = []
        if pc not in func_dict[func]:
            func_dict[func].append(pc) # add into list
            #print(pc)
    fd.close()

    multi_pc_cnt = 0
    for func, pc_list in func_dict.items():
        if len(pc_list) > 1:
            multi_pc_cnt += 1
        print func, pc_list
    print "func cnt: ", len(func_dict.keys())
    print "func cnt with many pcs: ", multi_pc_cnt

    #print(func_dict)


if __name__ == '__main__':
    log_name = "/tmp/decaf.log"
    parse_log(log_name)
     



