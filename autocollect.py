import threading
import sys
# import signal
# # this is the heavy monkey-patching that actually works
# # i.e. you can start the kernel fine and connect to it e.g. via
# # ipython console --existing
# signal.signal = lambda *args, **kw: None

import gc
import os, sys
import binaryninja as bn
import ctypes
import json
from binaryninja import scriptingprovider
import tempfile
import time
import difflib
from collections import defaultdict, OrderedDict
import collections

current_addr = 0x401000
current_view = "Graph:PE"
var_state = None
func_name = None
comment_state = None
highlight_state = None
data_state = None
dict_funcs = None
func_type = None
# eventfunc = time.time()
eventfunc2  = time.time()

def serialize(obj):
    """JSON serializer for objects not serializable by default json code"""

    return obj.__dict__

def printJSONFile(data):

    fullpath = "C:\\Users\\mozar\\Documents\\Work\\PhD\\JavaScript\\Binja-NodeJS\\jsondata.json"

    json_dump = json.dumps(data, sort_keys=True)

    try:
        # fullpath = os.path.join(tempfile.gettempdir(), 'jsondata.json')
        
        jf = open(fullpath, "a+")
        # jf.seek(0)
        # jf.truncate()
        jf.write(json_dump + "\n")
        jf.close()
    except IOError:
        print("ERROR: Unable to open/write to {}".format(fullpath))
    return 

class OrderedSet(collections.Set):
    def __init__(self, iterable=()):
        self.d = collections.OrderedDict.fromkeys(iterable)
    def __len__(self):
        return len(self.d)
    def __contains__(self, element):
        return element in self.d
    def __iter__(self):
        return iter(self.d)

def type_lookup(var_type):
	# arch = self.view.arch
	# arch_var = eval("self.view.arch")
    type_list = ['int16_t', 'int24_t', 'int32_t', 'char', 'void', 'uint16_t','uint24_t','uint32_t',
				'float8','float16','float24','float', 'double','float72','long double',
				'void*','void* const','void* volatile','void&','int32_t*']
    
    if (type_list.count(var_type) > 0):
        print("found var: {}".format(var_type))
        return True
    else:
        return False


def setValue(bip, bv):
    global current_addr, selChanged, current_view, var_state, func_name, comment_state, highlight_state, data_state, dict_funcs, func_type
    valueChanged = current_addr != bip.current_addr
    # print("{} {} {}".format(valueChanged, current_addr, bip.current_addr))
    # viewChanged = current_view != bv.file.view
    if (valueChanged): # or viewChanged):
        
        print("valueChanged")
        # var_state = func.vars
        update_ns(bip, bv)
        # eventfunc2  = time.time()
    current_addr = bip.current_addr
    current_view = bv.file.view
    try:
        if (bv.file.view == "Graph:PE" or bv.file.view == "Linear:PE"):     #Eventually, determine if bip is in the .text section
            var_state = bip.current_func.vars
            func_name = bip.current_func.symbol.name
            func_type = bip.current_func.return_type
            comment_state = bip.current_func.comments
            highlight_state = bip.current_func.get_instr_highlight(current_addr)

            # if ('call' in bv.get_disassembly(current_addr)):
                #get list of functions
            dict_funcs = func_types(bv)
                # print("-- selected a call")


        if (bv.file.view == "Hex:PE"):
            data_state = bv.read(bip.current_addr,1)
    except Exception as e:
        print("Found setValue exception {}".format(e))
        # sys.exit()          # Close thread
        #undefined functions have no vars
        


def update_ns(bip, bv):
    """Updates the namespace of the running kernel with the binja magic variables"""

    global current_addr, current_view

    print("[*] Printing view updates!")
    # print("{}".format(bip.write_at_cursor))
    # print("{}".format(bip.get_selected_data))
    # print("{}".format(bip.current_view))
    # print("File View: {}".format(bv.file.view))
    # print("Current Func: {}".format(str(bip.current_func)[11:-1]))
    # print("Current Block: {}".format(str(bip.current_block)[12:-1]))
    # print("Current Addr: 0x{:x}".format(int(bip.current_addr)))
    # print("Current Instr: {}".format(bip.current_addr))
    # print("Current Selection: 0x{:x}".format(int(bip.current_selection_begin)))
    # print("0x{0:x}, 0x{1:x}".format(int(bip.current_selection_begin), int(bip.current_selection_end)))
    # print(bip.current_func.low_level_il)
    # print(bip.current_func.medium_level_il)
    
    # data = {
    #     'type': 'view',
    #     'bv.file.view': bv.file.view,
    #     # 'bip.current_func': str(bip.current_func)[11:-1],
    #     # 'bip.current_block': str(bip.current_block)[12:-1],
    #     'address': "0x{:x}".format(int(bip.current_addr)),
    #     'oldaddress': "{}".format(current_addr),
    #     'oldview': current_view
    # }
    current_addr = hex(int(bip.current_addr))
    print("Current_addr: " + current_addr)
    current_view = bv.file.view

    # printJSONFile(data)
    return

# create dictionary of address, type, name for binary
def func_types(bv):
    s = []
    tup_master = ()
    for func in bv.functions:
        tup_temp = (str(func)[11:-1], str(func.return_type))
        s.append(tup_temp)
        tup_temp2 = (str(func)[11:-1], str(func.name))
        s.append(tup_temp2)

    d = defaultdict(list)
    for k, v in s:
        d[k].append(v)
    # list(d.items()) = [('_start', ['uint32_t', '0x401000']), ....
    return d
    
def diff_func_types(a, b):
    # Change function type 
    diff_change = 0
    set_diff = None
    print("in diff_func_types "+ a, b)
    for i in a:
        diff = set(a[i]) - set(b[i])    
        if (len(diff) > 0):
            diff_change = diff
            set_diff = set(a[i])
    print("diff_func_types" +  diff_change, set_diff)
    return diff_change, set_diff

    # Changed func name
    # diff_keys = a.keys() - b.keys()     # {1, '_startIO'}
    # func_renamed = list(diff_keys)[1]   # '_startIO'

def start_watch(bv):

    obj = [o for o in gc.get_objects() if isinstance(o, scriptingprovider.PythonScriptingInstance.InterpreterThread)]
    if len(obj) == 1:
        bip = obj[0]
    else:
        raise Exception("Couldn't find scriptingprovider. Sure you are in the right kernel?")

    setValue(bip, bv)
    # update_ns(bip, bv)
    threading.Timer(1, start_watch, [bv]).start()

def func_updated(bv, function):
    global eventfunc2, var_state, current_addr, func_name, comment_state, highlight_state, dict_funcs
    data = OrderedDict()
    temp_name = 0
    temp_type = 0

    # bv.update_analysis()
    # eventfunc2 = time.time()

    try:
            # if (eventfunc + 1 < time.time()):
            print("{} {}".format(hex(int(bv.get_functions_containing(current_addr)[0].start)), str(function)))
            #print("function {}".format(hex(int(function.start))))
            # print("{}".format(eventfunc2))
            # if (bv.file.view == "Graph:PE" or bv.file.view == "Linear:PE"):
            if (eventfunc2 + 1 < time.time()):
                #Check for var name collision (caused spurious var entries)
                if (str(bv.get_functions_containing(current_addr)) != str(function)):
                    var_state = function.vars
                # print('[*] Updated function {name}'.format(name=function.symbol.name))

                # Local Var name/type change
                for item,var in enumerate(var_state):
                    if (str(var_state[item].name) != str(function.vars[item].name)) and temp_name == 0:
                        print("[] Name change: {} {}".format(function.vars[item].name, item))
                        var_type_new, var_name_new, index = function.vars[item].type, function.vars[item].name, item
                        var_type_old, var_name_old = var_state[item].type, var_state[item].name
                        temp_name = 1
                    if (str(var_state[item].type) != str(function.vars[item].type)) and temp_type == 0:
                        print("[] Type change: {} {}".format(function.vars[item].type, item))
                        var_type_new, var_name_new, index = function.vars[item].type, function.vars[item].name, item
                        var_type_old, var_name_old = var_state[item].type, var_state[item].name
                        temp_type = 1

                # Local Var name/type change
                if (temp_name == 1 and temp_type == 1):
                    print("[*] Var_Updated: func:{} func_addr:{} var_name_new:{} var_type_new:{} var_name_old:{} var_type_old:{}"
                            .format(function.symbol.name, str(function)[11:-1], var_name_new, var_type_new, var_name_old, var_type_old))
                    data = {
                        'type': 'var_updated',
                        'function': str(function.symbol.name),
                        'func_addr': hex(int(function.start)),
                        'var_name_new': str(var_name_new),
                        'var_type_new': str(var_type_new),
                        'var_name_old': str(var_name_old),
                        'var_type_old': str(var_type_old),
                        'index': str(index),
                        'view': current_view
                    }
                    printJSONFile(data)
                elif temp_type == 1:
                    data = {
                        'type': 'var_type_updated',
                        'function': str(function.symbol.name),
                        'func_addr': hex(int(function.start)),
                        'var_name_new': str(var_name_new),
                        'var_type_new': str(var_type_new),
                        'var_name_old': str(var_name_old),
                        'var_type_old': str(var_type_old),
                        'index': str(index),
                        'view': current_view
                    }
                    printJSONFile(data)
                elif temp_name == 1:
                    data = {
                        'type': 'var_name_updated',
                        'function': function.symbol.name,
                        'func_addr': hex(int(function.start)),
                        'var_name_new': str(var_name_new),
                        'var_type_new': str(var_type_new),
                        'var_name_old': str(var_name_old),
                        'var_type_old': str(var_type_old),
                        'index': str(index),
                        'view': current_view
                    }
                    printJSONFile(data)
                var_state = function.vars
                # eventfunc = time.time()

                # Function name/type change 
                # Rememeber what the func name/type were first (dict_funcs), then send new and old
                dict_funcs_new = func_types(bv)
                new_key_diff, new_set_diff = diff_func_types(dict_funcs_new, dict_funcs)
                print("new_key_diff,  {} {}".format(new_key_diff))
                if (new_key_diff > 0):
                # if(func_name == function.symbol.name):
                #     print("Func Name Same") 
                # if (func_name != function.symbol.name):
                    # print("Func Name Different")
                    # dict_funcs_new = func_types(bv)
                    # print(dict_funcs_new)
                    # new_key_change, new_key_diff = diff_func_types(dict_funcs_new, dict_funcs)
                    
                    print('[*] Updating function name {}'.format(function))
                    print("func_new: {} {} {}".format(new_key_change, new_key_diff, new_set_diff))
                    old_key_change, old_key_diff, old_set_diff = diff_func_types(dict_funcs, dict_funcs_new)
                    print("func_old: {} {} {}".format(old_key_change, old_key_diff, old_set_diff))

                    if (old_key_change != 0 and new_key_change != 0):
                        # eventfunc2 = time.time()  #skip next updates (call updates in other functions)
                        # Name change
                        print("keydiff: {} {}".format(old_key_diff, new_key_diff))
                        if (str(old_key_diff) != str(new_key_diff)):
                            print("**** Name updated****")
                            # print(str(list(new_set_diff)))
                            # The order of the old_set_diff list is swapped the first time... sometimes
                            if (str(list(new_set_diff)[1]) == str(list(old_set_diff)[1])):
                                data = {
                                    'type': 'func_name_updated',
                                    'func_addr': str(old_key_change),
                                    'function_name_new': str(new_key_diff)[6:-3],
                                    'function_name_old': str(old_key_diff)[6:-3],
                                    'function_type_new': str(list(new_set_diff)[1]),
                                    'function_type_old': str(list(old_set_diff)[1]),
                                    'view': current_view
                                }
                            else:
                                data = {
                                    'type': 'func_name_updated',
                                    'func_addr': str(old_key_change),
                                    'function_name_new': str(new_key_diff)[6:-3],
                                    'function_name_old': str(old_key_diff)[6:-3],
                                    'function_type_new': str(list(new_set_diff)[1]),
                                    'function_type_old': str(list(old_set_diff)[0]),
                                    'view': current_view
                                }
                        # Name and Type change
                        elif (len(list(new_key_diff)) > 1):
                            print("**** Name and Type change ****")
                            if (type_lookup(list(old_key_diff)[0])):
                                # First element in old set is the type
                                data = {
                                    'type': 'func_name_type_updated',
                                    'func_addr': str(old_key_change),
                                    'function_name_new': str(list(new_set_diff)[0]),
                                    'function_name_old': str(list(old_key_diff)[1]),
                                    'function_type_new': str(list(new_set_diff)[1]),
                                    'function_type_old': str(list(old_set_diff)[0]),
                                    'view': current_view
                                }
                            else:
                                # Second element in old set is the type
                                data = {
                                    'type': 'func_name_type_updated',
                                    'func_addr': str(old_key_change),
                                    'function_name_new': str(list(new_set_diff)[0]),
                                    'function_name_old': str(list(old_key_diff)[0]),
                                    'function_type_new': str(list(new_set_diff)[1]),
                                    'function_type_old': str(list(old_set_diff)[1]),
                                    'view': current_view
                                }

                        # Type change
                        else: #if (str(list(old_set_diff)[1]) != str(list(new_set_diff)[1])):
                            print("**** Type updated****")
                            data = {
                                'type': 'func_type_updated',
                                'func_addr': str(old_key_change),
                                'function_name_new': str(list(new_set_diff)[0]),
                                'function_name_old': str(list(old_set_diff)[0]),
                                'function_type_new': str(list(new_set_diff)[1]),
                                'function_type_old': str(list(old_set_diff)[1]),
                                'view': current_view
                            }
                        dict_funcs = dict_funcs_new
                        eventfunc2 = time.time()
                        # func_name = function.symbol.name
                        printJSONFile(data)
                    

                #Comment state change
                if ((comment_state != function.comments)):
                    address, comment, comment_text = None, None, None
                    comment_state_len = len(comment_state)
                    new_comment_len = len(function.comments)
                    print("Comment change {} {}".format(comment_state_len, new_comment_len))
                    print("comment_state: {}".format(comment_state))
                    print("function.comments: {} {}".format(function, function.comments))
                    # Added
                    if (comment_state_len < new_comment_len or comment_state_len == new_comment_len):
                        for item in function.comments.items():
                            if item not in comment_state.items():
                                address = item[0]
                                comment = item[1]
                                comment_text = "comment_changed"
                                print("[*] Comment changed: {}".format(comment))
                    
                        #check for __stdcall
                        string_start = 8
                        if (str(function)[9] == "_"):
                            string_start = 18

                        if not comment_state.values():
                            data = {
                                'type': comment_text,
                                'func': hex(int(function.start)),
                                'addr': hex(int(address)),
                                'comment_new': comment,
                                'comments_old': "",
                                'view': current_view
                            }
                        else: 
                            data = {
                                'type': comment_text,
                                'func': hex(int(function.start)),
                                'addr': hex(int(address)),
                                'comment_new': comment,
                                'comments_old': comment_state.values().pop(0),
                                'view': current_view
                            }
                    
                    # Removed comment
                    elif (comment_state_len > new_comment_len):
                        for item in comment_state.items():
                            if item not in function.comments.items():
                                address = item[0]
                                comment = item[1]
                                comment_text = "comment_removed"
                                print("[*] Comment removed: {}".format(comment))
                                data = {
                                    'type': comment_text,
                                    'func': hex(int(function.start)),
                                    'addr': hex(int(address)),
                                    'comment_new': "",
                                    'comments_old': comment,
                                    'view': current_view
                                }
                    comment_state = function.comments
                    printJSONFile(data)

                # Highlight change:
                if (str(highlight_state) != str(function.get_instr_highlight(current_addr))):
                    print("[*] Highlight change: {} {}".format(hex(int(current_addr)), function.get_instr_highlight(current_addr)))
                    print("highlight_state: {}".format(highlight_state))
                    print("get_instr_highlight: {}".format(function.get_instr_highlight(current_addr)))
                    
                    color_old, color_new = color_matching(str(highlight_state), str(function.get_instr_highlight(current_addr)))
                    
                    data = {
                        'type': "highlight",
                        'func': hex(int(function.start)),
                        'addr': hex(int(current_addr)),
                        'color_new': color_old,
                        'color_old': color_new,
                        'view': current_view
                    }
                    highlight_state = function.get_instr_highlight(current_addr)
                    printJSONFile(data)
                    
            else:
                print("Skipping func_updated1")
    # else:
    #     print("Skipping func_updated2")
    except Exception as e:
        print("Exception: skipping func_update: {}".format(e))

def color_matching(color_old, color_new):
    colors_dict = {'none':'NoHighlightColor', 'black':'BlackHighlightColor', 'blue':'BlueHighlightColor', 
                    'cyan':'CyanHighlightColor', 'green': 'GreenHighlightColor', 'magenta': 'MagentaHighlightColor',
                    'orange': 'OrangeHighlightColor', 'red': 'RedHighlightColor', 'white': 'WhiteHighlightColor',
                    'yellow': 'YellowHighlightColor'}

    _old_color=color_old.split(':')[1].split()[0][:-1]
    _new_color=color_new.split(':')[1].split()[0][:-1]

    print(_old_color, _new_color)
    old_color = colors_dict.get(_old_color, color_old)
    new_color = colors_dict.get(_new_color, color_new)

    return old_color, new_color

def func_added(bv, function):
    global eventfunc2

    if (eventfunc2 + 2 < time.time()):
        data = OrderedDict()
        print("[*] Function Added: {}".format(function.symbol.name))
        data = {
            'type': 'func_added',
            'function': function.symbol.name,
            'func_addr': str(function)[11:-1],
            'view': current_view
        }
        eventfunc2 = time.time()
        printJSONFile(data)

def func_removed(bv, function):
    global eventfunc2

    if (eventfunc2 + 1 < time.time()):
        data = OrderedDict()
        print("[*] Function Removed: {}".format(function.symbol.name))
        data = {
            'type': 'func_removed',
            'function': function.symbol.name,
            'func_addr': str(function)[11:-1],
            'view': current_view
        }
        eventfunc2 = time.time()
        printJSONFile(data)

def data_written(bv, address, length):
    global eventfunc2, data_state#, eventfunc

    if (eventfunc2 + 1 < time.time()):
        data = OrderedDict()
        print('[*] Data Written <0x{name:x}> {length}'.format(name=address, length=length))
        # eventfunc = time.time()
        
        data_new = bv.read(address, 1)
        print("new data: {} old data: {}".format(data_new, data_state))
        data = {
            'type': 'data_written',
            'address': "0x{:x}".format(int(address)),
            'length': str(length),
            'data_old': str(data_state),
            'data_new': str(data_new),
            'view': current_view
        }

        printJSONFile(data)
        eventfunc2 = time.time()

    else:
        pass

event = time.time()

def type_defined(bv, name, type):
    global event, eventfunc2
    
    if (event + 1 < time.time()):
        if (eventfunc2 + 1 < time.time()):
            data = OrderedDict()
            print('[*] Type Defined')
            event = time.time()
            # print(event)
            data = {
                'type': 'type_defined',
                'name': str(name),
                'type_defined': str(type),
                'view': current_view
            }

            printJSONFile(data)

    else:
        print('[*] Type Defined - skipping')
        pass

def type_undefined(bv, name, type):
    global event, eventfunc2

    if (event + 1 < time.time()):
        if (eventfunc2 + 1 < time.time()):
            data = OrderedDict()
            print('[*] Type Undefined')
            print(event)
            data = {
                'type': 'type_undefined',
                'name': str(name),
                'type2': str(type),
                'view': current_view
            }

            printJSONFile(data)
        
    else:
        print('[*] Type Undefined - skipping')
        pass

def data_var_added(bv, var):
    global eventfunc2

    if (eventfunc2 + 1 < time.time()):
        data = OrderedDict()
        print('[*] Data_var_added')
        data = {
            'type': 'data_var_added',
            'var': str(var),
            'view': current_view
        }
        eventfunc2 = time.time()
        printJSONFile(data)

    else:
        print('[*] Data Var Added - skipping')
        pass

def data_var_removed(bv, var):
    global eventfunc2

    if (eventfunc2 + 1 < time.time()):
        data = OrderedDict()
        print('[*] Data_var_removed')
        data = {
            'type': 'data_var_removed',
            'var': str(var),
            'view': current_view
        }
        eventfunc2 = time.time()
        printJSONFile(data)
    else:
        print('[*] Data Var Removed - skipping')
        pass

# Phased out
# def make_comm(bv, address):
#     global eventfunc, current_addr
#     print('[*] Changing comment <0x{name:x}>'.format(name=address))

#     data = OrderedDict()
#     comment = bn.get_text_line_input(
# 		"Insert Comment", "Enter comment:")

#     if (comment is None):
#         pass
#     else:
#         # text_f = bn.MultilineTextField("Insert Comment")
#         # comment = bn.get_form_input(text_f, "the options")
#         eventfunc = time.time()
#         start_addr = bv.get_previous_function_start_before(int(address))
#         print("start_addr: {}".format(start_addr))
        
#         func = bv.get_function_at(int(start_addr))
#         print("func: {}".format(func))

#         oldcomm = func.get_comment_at(address)
#         func.set_comment_at(address, comment)
#         current_addr = hex(int(address))
#         print("comment current_addr: " + str(current_addr))
#         current_view = 'Graph:PE'

#         data = {
#             'type': 'comment',
#             'address': "0x{:x}".format(int(address)),
#             'comment': comment,
#             'oldcomment': oldcomm,
#             'view': bv.view
#         }

#         printJSONFile(data)

# Phased out - Manual plugin selection
# def func_name(bv, function):
    # global eventfunc, eventfunc2, current_addr, current_view

    # print('[*] Changing function {name}'.format(name=function.symbol.name))
    # print('function: {}'.format(function))

    # # function_name = bn.get_text_line_input(
    # #     "Change Function Name", "Enter function name:")

    # eventfunc2 = time.time()

    # data = {
    #     'type': 'func',
    #     'function': function.symbol.name,
    #     'func_addr': str(function)[11:-1],
    #     'new_function': function_name
    # }
    # temp = str(function)[11:-1]
    # print("temp: " + temp)
    # current_addr = hex(int(temp, 16))
    # print("func current_addr: " + str(current_addr))
    # current_view = 'Graph:PE'
    # function.name = function_name
    # printJSONFile(data)


