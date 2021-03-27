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
}