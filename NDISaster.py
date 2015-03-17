from idaapi import *
import idautils
import idc

def m(var):
	return var & 0xffffffff

def get_instruction_dictionary(ea):
	insts = dict()
	for func in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
		f_end = FindFuncEnd(func)
		for head in Heads(func, f_end):
			if not isCode(GetFlags(head)):
				continue
			mnem = GetMnem(head)
			if mnem not in insts:
				insts[mnem] = list()
			insts[mnem].append(head)
	return insts

def get_refs_to_func(name, insts):
	refs = list()
	for loc in insts["call"]:
		if name in GetOpnd(loc, 0):
			refs.append(loc)
	return refs

def get_sid_or_load_til(name):
	new_sid = GetStrucIdByName(name)
	if new_sid == m(-1):
		new_sid = Til2Idb(-1, name) # Will return -1 if no struct in TIL
	return new_sid

def change_member_type_at_offset(frame, name, new_sid, offset):
	sptr = get_struc(new_sid)
	ti = opinfo_t()
	ti.tid = sptr.id
	struct_size = get_struc_size(sptr)
	del_struc_members(frame, offset, offset + struct_size)
	add_struc_member(frame, name, offset, struflag(), ti, struct_size)

def swap_structs_in_stack(ref, name, new_sid):
	frame = get_frame(ref)
	frame_members = StructMembers(frame.id)
	offset = 0
	for frame_member in frame_members:
		if frame_member[1] == name: # frame_member[1] == frame_member name
			offset = frame_member[0] # frame_member[0] == Member offset
			break
	if not offset:
		return -1
	change_member_type_at_offset(frame, name, new_sid, offset)

def get_insts_in_function(insts, target, func_start):
	insts_in_func = list()
	func_end = FindFuncEnd(func_start)
	for inst in insts[target]:
		if not func_end > inst > func_start:
			continue
		insts_in_func.append(inst)
	return insts_in_func


def func_len(func_start):
	func_end = FindFuncEnd(func_start)
	return func_end - func_start

def rename_handler_functions(ref, insts, target_struct_name, handler_function_prefix):
	func_start = get_func(ref).startEA
	AnalyzeArea(func_start, FindFuncEnd(func_start))
	for inst in get_insts_in_function(insts, "mov", func_start):
		if not GetOpType(inst, 0) == o_displ:
			continue
		if not GetOpType(inst, 1) == o_imm:
			continue
		destination_operand = GetOperandValue(inst, 1)
		if not isFunc(GetFlags(destination_operand)):
			continue
		stack_operand = GetOpnd(inst, 0)
		if not "[ebp+" + target_struct_name + "." in stack_operand:
			continue
		# We're parsing a string of this type: "[ebp+ProtocolCharacteristics.Ndis40Chars.PnPEventHandler]"
		func_name = stack_operand.split(".")[-1][:-1]
		MakeName(destination_operand, handler_function_prefix + func_name)
		print "[+] %s: %08x" % (handler_function_prefix + func_name, destination_operand)

def correct_struct_definitions(new_defs):
	insts = get_instruction_dictionary(GetEntryOrdinal(0))
	for new_def in new_defs:
		function_name = new_def[0]
		new_function_type = new_def[1]
		target_struct_name = new_def[2]
		new_struct_type = new_def[3]
		handler_function_prefix = new_def[4]
		refs = get_refs_to_func(function_name, insts)
		if not len(refs):
			print "[-] No calls found for function %s" % (function_name)
			continue
		for ref in refs:
			SetType(GetOperandValue(ref, 0), new_function_type)
			if new_struct_type and target_struct_name:
				new_sid = get_sid_or_load_til(new_struct_type)
				if new_sid == m(-1):
					print "[-] Can't find type %s in TIL" % (new_struct_type)
					continue
				swap_structs_in_stack(ref, target_struct_name, new_sid)
			if target_struct_name and handler_function_prefix:
				rename_handler_functions(ref, insts, target_struct_name, handler_function_prefix)

def generate_script_prelude(mod_name):
	return '.printf "[Packet dump start]"; .echo; .printf "base_addr=%08x", ' + "%s; .echo;" % (mod_name)

def generate_initial_breakpoint(mod_name, func):
	return 'bp %s+%08x "' % (mod_name, func - 0x10000)

def generate_windbg_dump_received_packet():
	# This goes through the MDL cyclically until all packet portions are dumped
	return 'r $t4 = poi(esp+8); r $t5 = poi($t4 + 8);.printf \\"[Received packet dump]\\"; .echo; .while (@$t5 != 0) {db poi($t5 + c) L poi($t5 + 14); r $t5 = poi($t5);}; .printf \\"[End packet dump]\\"; .echo;'

def generate_windbg_dump_fuzz_packet():
	return 'r $t4 = poi(esp+8); r $t5 = poi($t4 + 8); r $t7 = poi(poi($t5 + c) + 6); .if (@$t7 == 44332211) {.printf \\"[Received packet dump]\\"; .echo; .while (@$t5 != 0) { db poi($t5 + c) L poi($t5 + 14); r $t5 = poi($t5);}; .printf \\"[End packet dump]\\";.echo;'

def generate_single_breakpoint(mod_name, func):
	global breakpoint_list
	global breakpoint_count
	breakpoint_count += 1
	breakpoint_list.append(func)
	return 'bp %s+%08x \\"r eip; g\\";' % (mod_name, func - 0x10000) # 0x10000 is an arbitrary Ida offset 

def generate_packet_trace_breakpoints(mod_name, func, insts):
	global breakpoint_list
	out_script = ""
	for call_inst in get_insts_in_function(insts, "call", func):
		if GetOpType(call_inst, 0) != o_near:
			continue
		called_func = GetOperandValue(call_inst, 0)
		if called_func in breakpoint_list:
			continue
		if func_len(called_func) > 170:
			out_script += generate_single_breakpoint(mod_name, called_func)
		# Call this function recursively to get all inner calls of the targeted function
		out_script += generate_packet_trace_breakpoints(mod_name, called_func, insts)
	return out_script

def generate_final_breakpoint(mod_name, func, insts, fuzz):
	global breakpoint_count
	out_script = ""
	i = 1
	for retn_inst in get_insts_in_function(insts, "retn", func):
		# clear all the breakpoints except the first on retn
		out_script += 'bp %s+%08x \\"bc 1-%d; g\\";' % (mod_name, retn_inst - 0x10000, breakpoint_count + i)
		i += 1
	if fuzz:
		out_script += '}; g"; g' # Close the .if clause!
	else:
		out_script += 'g"; g' # Close the script
	return out_script


def generate_windbg_packet_trace_script(mod_name, func, out_file, fuzz):
	global breakpoint_count
	global breakpoint_list
	breakpoint_count = 0
	breakpoint_list = list()
	out_script = ""
	func = LocByName(func)
	insts = get_instruction_dictionary(func)
	out_script += generate_script_prelude(mod_name)
	out_script += generate_initial_breakpoint(mod_name, func)
	if fuzz:
		out_script += generate_windbg_dump_fuzz_packet()
	else:
		out_script += generate_windbg_dump_received_packet()
	out_script += generate_packet_trace_breakpoints(mod_name, func, insts)
	out_script += generate_final_breakpoint(mod_name, func, insts, fuzz)
	if not out_file:
		return out_script
	else:
		f = open(out_file, "w")
		f.write(out_script)
		f.close()
		print "[+] Wrote WDS script to file, total %d breakpoints" % (breakpoint_count)

def parse_windbg_input(in_file):
	packet_dict = dict()
	f = open(in_file, "r")
	packet_mode = False
	added_lines = False
	read_packet = False
	base_addr = 0
	for line in f:
		line = line.rstrip("\r\n")
		if "base_addr=" in line:
			base_addr = int(line.split("=")[1], 16)
			continue
		if "[Received packet dump]" in line:
			packet_contents = ""
			packet_mode = True
			read_packet = False
			continue
		if packet_mode and not "[End packet dump]" in line:
			line = ''.join(line[10:].split("  ")[0].replace("-"," ").split(" ")) # Just get the packet hex
			packet_contents += line
			added_lines = True
			continue
		if "[End packet dump]" in line:
			packet_mode = False
			if added_lines:
				added_lines = False
				packet_dict[packet_contents] = list()
				read_packet = True
			continue
		if "eip=" in line:
			if read_packet:
				addr = int(line[4:], 16)
				packet_dict[packet_contents].append(addr - base_addr + 0x10000) # The constant offset in Ida
			continue
	f.close()
	return packet_dict

def generate_func_prefix(packet):
	func_prefix = ""
	ethtype = packet[12*2:14*2] 
	if ethtype == "dd86" or ethtype == "86dd":
		func_prefix = "_IPv6_"
	elif ethtype == "0800":
		func_prefix = "_IPV4_"
	elif ethtype == "0806":
		func_prefix = "_ARP_"
	if ethtype == "0800":
		protocol = packet[23*2:24*2]
		if protocol == "11":
			func_prefix += "UDP_"
		elif protocol == "06":
			func_prefix += "TCP_"
	return func_prefix

def import_windbg_packet_trace(in_file):
	packet_dict = parse_windbg_input(in_file)
	for packet in packet_dict.keys():
		func_prefix = generate_func_prefix(packet)
		if func_prefix:
			for func in packet_dict[packet]:
				old_name = Name(func)
				if func_prefix not in old_name:
					MakeName(func, func_prefix + old_name)

breakpoint_count = 0
breakpoint_list = list()

nrpType = "VOID NdisRegisterProtocol(PNDIS_STATUS Status, PNDIS_HANDLE NdisProtocolHandle, __NDIS_PROTOCOL_CHARACTERISTICS* ProtocolCharacteristics, UINT CharacteristicsLength);"
nirlmType = "NDIS_STATUS NdisIMRegisterLayeredMiniport(NDIS_HANDLE NdisWrapperHandle, PNDIS_MINIPORT_CHARACTERISTICS MiniportCharacteristics, UINT CharacteristicsLength, PNDIS_HANDLE DriverHandle);"

new_defs = [("NdisRegisterProtocol", nrpType, "ProtocolCharacteristics", "__NDIS_PROTOCOL_CHARACTERISTICS", "Pr_"), ("NdisIMRegisterLayeredMiniport", nirlmType, "MiniportCharacteristics", 0, "Mp_")]
correct_struct_definitions(new_defs)