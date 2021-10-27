import binaryninja as bn
from .parsing import data_var_added, \
	data_written, data_var_removed, \
	func_added, func_removed, func_updated, \
	type_defined, type_lookup, type_undefined


class myNotification(bn.BinaryDataNotification):
	def __init__(self, view):
		self.view = view
		pass

	def data_written(self, view, offset, length):
		print("data_written: ", view, offset, length)
		data_written(view, offset, length)
		pass

	def data_inserted(self, view, offset, length):
		print("data_inserted: ", view, offset, length)
		pass

	def data_removed(self, view, offset, length):
		print("data_removed: ", offset, length)
		pass

	def function_added(self, view, func):
		print("function_added: ", func)
		func_added(view, func)
		pass

	def function_removed(self, view, func):
		print("function_removed: ", func)
		func_removed(view, func)
		pass

	def function_updated(self, view, func):
		# print("function_updated", hex(int(func.start)))
		func_updated(view, func)
		pass

	def data_var_added(self, view, var):
		data_var_added(view, var)
		print("var_added: ", var)
		pass

	def data_var_removed(self, view, var):
		data_var_removed(view, var)
		print("var_removed: ", var)
		pass

	def data_var_updated(self, view, var):
		print("var_updated: ", var)
		pass

	def string_found(self, view, string_type, offset, length):
		print("string_found: ", string_type, offset, length)
		pass

	def string_removed(self, view, string_type, offset, length):
		print("string_removed: ", string_type, offset, length)
		pass

	def type_defined(self, view, name, type):
		global type_flag
		type_defined(view, str(name), type)
		print("type_defined: ", name, type)
		pass

	def type_undefined(self, view, name, type):
		global type_flag
		type_undefined(view, str(name), type)
		print("type_undefined: ", name, type)
		pass
