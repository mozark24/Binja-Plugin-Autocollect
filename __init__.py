"""
1. Load Binary Ninja
2. Verify no errors in start-up
3. Open executable for analysis
4. Tools > Start server
5. View > Script console  (Ctrl + `)
6. Enter:
import xmlrpc
s = xmlrpc.client.ServerProxy('http://localhost:1337')
7. Access commands:
s.FuncName('0x401021', 'new')
s.FuncType('0x401021','uint32_t')	
s.SetColor(0x40101b,'CyanHighlightColor')
s.Jump('0x40101b', 'Graph:PE')
s.SetFunc('0x401477', 'NewFunc')
s.MakeComm('0x401019', "Important call here!", '0x401000')
s.Undo()
s.Redo()
s.version()
s.shutdown()
s.system.listMethods()
['Jump', 'MakeComm', 'SetColor', 'Sync', 'shutdown', 'system.listMethods', 'system.methodHelp', 'system.methodSignature', 'version']

8. Get view of main screen:
print bv.file.view
9.  Change view of main screen:
>>> bv.file.view = 'Linear:PE'
>>> bv.file.view = 'Strings:PE'
>>> bv.file.view = 'Strings:PE'
>>> bv.file.view = 'Hex:PE'

"""
from .collectors.notification import myNotification
from .collectors.parsing import *

started = False
t = None
#_breakpoints = set()
_current_instruction = 0
func_hold = "test"
type_flag = 0

PAGE_SZ = 0x1000


def expose(f):
	"Decorator to set exposed flag on a function."
	f.exposed = True
	return f


def is_exposed(f):
	"Test whether another function should be publicly exposed."
	return getattr(f, 'exposed', False)


def ishex(s):
	return s.startswith("0x") or s.startswith("0X")


if False:
	class RequestHandler(SimpleXMLRPCRequestHandler):
		rpc_paths = ("/RPC2",)

		def do_OPTIONS(self):
			self.send_response(200)
			self.end_headers()

		# Add these headers to all responses
		def end_headers(self):
			self.send_header("Access-Control-Allow-Headers",
							 "Origin, X-Requested-With, Content-Type, Accept")
			self.send_header("Access-Control-Allow-Origin", "*")
			SimpleXMLRPCRequestHandler.end_headers(self)


def start_service(host, port, bv):
	if False:
		print("[+] Starting service on {}:{}".format(host, port))
		server = SimpleXMLRPCServer((host, port),
									requestHandler=RequestHandler,
									logRequests=False,
									allow_none=True)
		server.register_introspection_functions()
		server.register_instance(Bookmark(server, bv), allow_dotted_names=True)
		print("[+] Registered {} functions.".format( len(server.system_listMethods()) ))
		while True:
			if hasattr(server, "shutdown") and server.shutdown==True: break
			server.handle_request()
	return


def start_server(bv):
	if False:
		global t, started
		t = threading.Thread(target=start_service, args=(HOST, PORT, bv))
		t.daemon = True
		print("[+] Creating new thread {}".format(t.name))
		t.start()

		started = True
		return


def stop_server(bv):
	if False:
		global t
		t.join()
		t = None
		print("[+] Server stopped")
	return


def server_start_stop(bv):
	if t is None:
		if False:
			start_server(bv)
		bn.show_message_box(
			"Serv",
			"Service successfully started, you can now connect to it",
			bn.MessageBoxButtonSet.OKButtonSet,
			bn.MessageBoxIcon.InformationIcon
		)
		register_stuff(bv)				 
	else:
		if False:
			try:
				cli = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(HOST, PORT))
				cli.shutdown()
			except socket.error:
				pass
		stop_server(bv)
		bn.show_message_box(
			"Serv",
			"Service successfully stopped",
			bn.MessageBoxButtonSet.OKButtonSet,
			bn.MessageBoxIcon.InformationIcon
		)
	return

if False:
	class Bookmark:
		"""
		Top level class where exposed methods are declared.
		"""

		def __init__(self, server, bv, *args, **kwargs):
			self.server = server
			self.view = bv
			self.base = bv.entry_point & ~(PAGE_SZ-1)
			self._version = ("Binary Ninja", bn.core_version)
			self.old_bps = set()
			return


		def _dispatch(self, method, params):
			"""
			Plugin dispatcher
			"""
			func = getattr(self, method)
			if not is_exposed(func):
				raise NotImplementedError('Method "%s" is not exposed' % method)

			if DEBUG:
				print("[+] Executing %s(%s)" % (method, params))
			return func(*params)


		def _listMethods(self):
			"""
			Class method listing (required for introspection API).
			"""
			m = []
			for x in list_public_methods(self):
				if x.startswith("_"): continue
				if not is_exposed( getattr(self, x) ): continue
				m.append(x)
			return m


		def _methodHelp(self, method):
			"""
			Method help (required for introspection API).
			"""
			f = getattr(self, method)
			return inspect.getdoc(f)

		@expose
		def shutdown(self):
			""" shutdown() => None
			Cleanly shutdown the XML-RPC service.
			Example: binaryninja shutdown
			"""
			self.server.server_close()
			print("[+] XMLRPC server stopped")
			setattr(self.server, "shutdown", True)
			return 0

		@expose
		def version(self):
			""" version() => None
			Return a tuple containing the tool used and its version
			Example: binaryninja version
			"""
			return self._version

		def begin_undo(self):
			print("[+] Begin Undo")
			return self.view.begin_undo_actions()

		def commit_undo(self):
			print("[+] Commit Undo")
			return self.view.commit_undo_actions()

		@expose
		def Undo(self):
			""" Undo() => None
			Undo most recent action
			Example: binaryninja Undo
			"""
			autocollect.eventfunc2 = time.time()
			return self.view.undo()

		@expose
		def Redo(self):
			""" Redo() => None
			Redo most recent action
			Example: binaryninja Redo
			"""
			self.begin_undo()
			autocollect.eventfunc2 = time.time()
			self.redo_helper()
			return self.commit_undo()

		def redo_helper(self):
			return self.view.redo()


		def var_lookup(self, var_type):
			arch = self.view.arch
			# arch_var = eval("self.view.arch")
			type_dict = {'int16_t': bn.Type.int(2), 'int24_t':bn.Type.int(3), 'int32_t':bn.Type.int(4), 'char':bn.Type.char(),
							'void':bn.Type.void(), 'uint16_t':bn.Type.int(2,0),'uint24_t':bn.Type.int(3,0),'uint32_t':bn.Type.int(4,0),
							'float8':bn.Type.float(1),'float16':bn.Type.float(2),'float24':bn.Type.float(3),'float':bn.Type.float(4),
							'double':bn.Type.float(8),'float72':bn.Type.float(9),'long double':bn.Type.float(10),
							'void*':bn.Type.pointer(arch, bn.Type.void(),False, False, False),
							'void* const':bn.Type.pointer(arch,bn.Type.void(),True, False, False),
							'void* volatile':bn.Type.pointer(arch, bn.Type.void(),False, True, False),
							'void&':bn.Type.pointer(arch, bn.Type.void(),False, False, True),
							'int32_t*':bn.Type.pointer(arch, bn.Type.int(4),False, False, False)}

			new_type = type_dict.get(var_type)
			return new_type

		@expose
		def FuncVar(self, func_address, var_type, var_name, index):
			""" FuncVar(str func_address, string type (int32_t), string var_name, int var index
			s.FuncVar('0x401000', 'uint32_t', 'var_14', 0)
			"""
			autocollect.eventfunc2 = time.time()
			func = self.view.get_function_at(int(func_address,16))
			_var_type = self.var_lookup(var_type)
			# print(_var_type)
			self.Jump(func_address,'Graph:PE')			# Do I want to jump to that location?
			return func.create_user_var(func.vars[int(index)], _var_type, var_name)

		@expose
		def FuncName(self, address, funcName):
			""" SetFunc(int address, string funcName) => None
			Set Function name address to string
			s.FuncName('0x40102c', "new")
			"""
			autocollect.eventfunc2 = time.time()
			self.Jump(address,'Graph:PE')
			func = self.view.get_function_at(int(address,16)) 	#Only works for main function, not called
			func.name = funcName

		@expose
		def FuncNameType(self, address, funcName, var_type):
			""" SetFunc(int address, string funcName) => None
			Set Function name address to string
			import xmlrpc
			s = xmlrpc.client.ServerProxy('http://localhost:1337')
			s.FuncNameType('0x40102c', "new",'uint32_t')
			"""
			autocollect.eventfunc2 = time.time()
			self.Jump(address,'Graph:PE')
			func = self.view.get_function_at(int(address,16)) 	#Only works for main function, not called
			func.name = funcName
			temp_var = self.var_lookup(var_type)
			func.return_type = temp_var

		@expose
		def FuncType(self, address, var_type):
			""" s.FuncType('0x401021','int32_t')
			"""
			autocollect.eventfunc2 = time.time()
			func = self.view.get_function_at(int(address,16))
			temp_var = self.var_lookup(var_type)
			func.return_type = temp_var

		@expose
		def Jump(self, address, view):
			""" Jump(int addr) => None
			Move the EA pointer to the address pointed by `addr`.
			s.Jump('0x4049de','Graph:PE')
			"""
			# addr = long(address, 16) if ishex(address) else long(address)

			self.view.file.navigate(view, int(address,16))

		@expose
		def MakeComm(self, address, comment, function):
			""" MakeComm(str addr, string comment) => None
			Add a comment at the location `address`.
			s.MakeComm('0x401019', "Important call here!", '0x401000')
			"""
			autocollect.eventfunc2 = time.time()
			# addr = long(address, 16) if ishex(address) else long(address)
			# start_addr = self.view.get_previous_function_start_before(int(address,16))
			func = self.view.get_function_at(int(function,16))
			self.Jump(address,'Graph:PE')			# Do I want to jump to that location?
			# autocollect.eventfunc = time.time()
			# self.begin_undo()
			# self.makecomm_helper(func, addr, comment)
			# func = self.view.get_function_at(start_addr)
			return func.set_comment_at(int(address,16), comment)
			# return self.commit_undo()

		def do_command(self, cmd):
			print(cmd)
			return eval(cmd)

		@expose
		def SetColor(self, address, color):
			""" SetColor(int addr, string color) => None
			Set the location pointed by `address` with `color`.
			Example:  s.SetColor('0x401000', 'CyanHighlightColor')
			"""
			autocollect.eventfunc2 = time.time()
			start_addr = self.view.get_previous_function_start_before(int(address,16))
			func = self.view.get_function_at(start_addr)
			if func is None: return
			color_new = "bn.HighlightStandardColor."+color

			func.set_user_instr_highlight(int(address,16),eval(color_new))

		@expose
		def DefineFunc(self, address):
			""" str address must be the address of the function
			s.DefineFunc('0x401000')
			"""
			autocollect.eventfunc2 = time.time()
			self.view.create_user_function(int(address,16))
			self.view.file.navigate('Graph:PE', int(address,16))

		@expose
		def UndefineFunc(self, address):
			""" str address must be the address of the function
			s.UndefineFunc('0x401000')
			"""
			# global autocollect.eventfunc2
			autocollect.eventfunc2 = time.time()
			func = self.view.get_function_at(int(address,16))
			self.view.remove_user_function(func)
			self.view.file.navigate('Linear:PE', int(address,16))

		@expose
		def WriteData(self, address, data):
			self.view.file.navigate('Hex:PE', int(address,16))
			self.view.write(int(address, 16), data)

		@expose
		def AddType(self, name, var_type):

			_var_type = self.var_lookup(var_type)
			self.view.define_user_type(name, _var_type)

		@expose
		def RemoveType(self, name):
			self.view.undefine_user_type(name)


def on_complete(self):
	print("Analysis Complete")


def register_stuff(bv):
	notification = myNotification(bv)
	bv.register_notification(notification)
	start_watch(bv)
	# bn.AnalysisCompletionEvent(bv,on_complete)

# bn.PluginCommand.register("RegisterData", "", register_stuff)

bn.PluginCommand.register("Binja Start AutoCollect", "Binja Start AutoCollect", server_start_stop)
# bn.PluginCommand.register("Binja - Print View", "Binja Print Interactions_2", autocollect.start_watch)
# bn.PluginCommand.register_for_function("Binja - Change function", "Binja Change function name", autocollect.func_name)
# bn.PluginCommand.register_for_address("Binja - Make comment", "Binja Make comment", autocollect.make_comm)
