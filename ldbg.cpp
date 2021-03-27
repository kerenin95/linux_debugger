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


}