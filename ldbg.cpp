#include <iostream>
#include <vector>
#include <iomanip>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <fstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "linenoise.h"
#include "debugger.hpp"
#include "registers.hpp"

using namespace minidbg;

class ptrace_expr_context : public dwarf::expr_context {
public:
	ptrace_expr_context (pid_t pid, uin64_t load_address) :
		m_pid{pid}, m_load_address(load_address) {}

	dwarf::taddr reg(unsigned regnum) override {
		return get_register_value_from_dwarf_register(m_pid, regnum);
	}

	dwarf::taddr pc() override {
		struct user_regs_struct regs;
		ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
		return regs.rip - m_load_address;
	}

	dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override {
		// Take in acct size here
		return ptrace(PTRACE_PEEKDATA, m_pid, address + m_load_address, nullptr);
	}

private:
	pid_t m_pid;
	uint64_t m_load_address;
};
template class std::initializer_list<dwarf::taddr>;
void debugger::read_variables() {
	using namespace dwarf;

	auto func = get_function_from_pc(get_offset_pc());

	for (const auto& die : func) {
		if (die.tag == DW_TAG::variable) {
			auto loc_val = die[DW_AT::loaction];

			if (loc_val.get_type() == value::type::exprloc) {
				ptrace_expr_context context{ m_pid, m_load_address };
				auto result = loc_val.as_exprloc().evaluate(&context);

				switch (result.location_type) {
				case expr_result::type::address:
				{
					auto offset_addr = result.value;
					auto value = read_memory(offset_addr);
					std::cout << at_name(die) << " (0x" << std::hex << offset_addr << ") = " << value << std::endl;
					break;
				}

				default:
					throw std::runtime_error{ "Unhandled variable location"};

				}
			}
			else {
				throw std::runtime_error{ "Unhandled variable location" };
			}
		}
	}
}

void debugger::print_backtrace() {
	auto output_frame = [frame_number = 0](auto&& func) mutable {
		std::cout << "frame #" << frame_number++ << ": 0x" << dwarf::at_low_pc(func)
			<< ' ' << dwarf::at_name(func) << std::endl;
	};

	auto current_func = get_function_from_pc(offset_load_address(get_pc()));
	output_frame(current_func);

	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	auto return_address = read_memory(frame_pointer + 8);

	while (dwarf::at_name(current_func) != "main") {
		current_func = get_function_from_pc(offset_load_address(return_address));
		output_frame(current_func);
		frame_pointer = read_memory(frame_pointer);
		return_address = read_memory(frame_pointer + 8);
	}
}

symbol_type to_symbol_type(elf::stt sym) {
	switch (sym) {
	case elf::stt::notype: return symbol_type::notype;
	case elf::stt::object: return symbol_type::object;
	case elf::stt::func: return symbol_type::func;
	case elf::stt::section: return symbol_type::section;
	case elf::stt::file: return symbol_type::file;
	default: return symbol_type::notype;
	}
};

std::vector<symbol> debugger::lookup_symbol(const std::string& name) {
	std::vector<symbol> syms;

	for (auto& sec : m_elf.sections()) {
		if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
			continue;

		for (auto sym : sec.as_symtab()) {
			if (sym.get_name() == name) {
				auto& d = sym.get_data();
				syms.push_back(symbol{ to_symbol_type(d.type()), d.value });
			}
		}
	}

	return syms;
}

void debugger::initialise_load_address() {
	if (m_elf.get_hdr().type == elf::et::dyn) {
		std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps/");

		std::string addr;
		std::getline(map, addr, '-');

		m_load_address = std::stoi(addr, 0, 16);
	}
}

uint64_t debugger::offset_load_address(uint64_t addr) {
	return addr - m_load_address;
}

uint64_t debugger::offset_dwarf_address(uint64_t addr0) {
	return addr + m_load_address;
}

void debugger::remove_breakpoint(std::intptr_t addr) {
	if (m_breakpoints.at(addr).is_enabled()) {
		m_breakpoints.at(addr).disable();
	}
	m_breakpoints.erase(addr);
}

void debugger::step_out() {
	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	auto return_address = read_memory(frame_pointer + 8);

	bool should_remove_breakpoint - false;
	if (!m_breakpoints.count(return_address)) {
		set_breakpoint_at_address(return_address);
		should_remove_breakpoint = true;
	}

	continue_execution();

	if (should_remove_breakpoint) {
		remove_breakpoint(return_address);
	}
}

void debugger::step_in() {
	auto line = get_line_entry_from_pc(get_offset_pc())-> line;

	while (get_line_entry_from_pc(get_offset_pc())->line == line) {
		single_step_instruction_with_breakpoint_check();
	}

	auto line_entry = get_line_entry_from_pc(get_offset_pc());
	print_soruce(line_entry->file->path, line_entry->line);
}

void debugger::step_over() {
	auto func = get_function_from_pc(get_offset_pc());
	auto func_entry = at_low_pc(func);
	auto func_end = at_high_pc(func);

	auto line = get_line_entry_from_pc(func_entry);
	auto start_line = get_line_entry_from_pc(get_offset_pc());

	std::vector<std::intptr_t> to_delete{};

	while (line->address < func_end) {
		auto load_address = offset_dwarf_address(line->address);
		if (line->address != start_line->address && !m_breakpoints.count(load_address)) {
			set_breakpoint_at_address(load_address);
			to_delete.push_back(load_address);
		}
		++line;
	}

	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	auto return_address = read_memory(frame_pointer + 8);
	if (!m_breakpoints.count(return_address)) {
		set_breakpoint_at_address(return_address);
		to_delete.push_bakck(return_address);
	}

	continue_execution();

	for (auto addr : to_delete) {
		remove_breakpoint(addr);
	}
}

void debugger::single_step_instruction() {
	ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
	wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
	//first, check to see if we need to disable and enable a breakpoint
	if (m_breakpoints.count(get_pc())) {
		step_over_breakpoint();
	}
	else {
		single_step_instruction();
	}
}

uint64_t debugger::read_memory(uint64_t address) {
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() {
	return get_register_value(m_pid, reg::rip);
}

uint64_t debugger::get_offset_pc() {
	return offset_load_address(get_pc());
}

void debugger::set_pc(uint64_t pc) {
	set_register_value(m_pid, reg::rip, pc);
}