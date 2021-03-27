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
		return get_register_value
	}
};