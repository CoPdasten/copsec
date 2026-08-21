#include "process_monitor.hpp"
#include "logger.hpp"
#include "siem_exporter.hpp"

#include <algorithm>
#include <iterator>
#include <csignal>
#include <pwd.h>
#include <unistd.h>

namespace copsec {

ProcessMonitor::ProcessMonitor(EbpfMonitor& monitor) : monitor_(monitor) {}

void ProcessMonitor::start() {
    if (running_.exchange(true)) return;
    monitor_.set_exec_callback([this](const EbpfMonitor::ExecEvent& event) { inspect(event); });
}

void ProcessMonitor::stop() {
    if (!running_.exchange(false)) return;
    monitor_.set_exec_callback({});
}

std::uint64_t ProcessMonitor::blocked_count() const { return blocked_.load(); }

bool ProcessMonitor::suspicious_binary(const std::string& filename) {
    const auto slash = filename.find_last_of('/');
    const std::string basename = slash == std::string::npos ? filename : filename.substr(slash + 1);
    static const char* names[] = {"sh", "bash", "nc", "netcat", "ncat", "python", "python3",
        "perl", "ruby", "whoami", "id", "curl", "wget"};
    return std::any_of(std::begin(names), std::end(names), [&basename](const char* name) {
        return basename == name || (std::string(name) == "python" && basename.rfind("python", 0) == 0);
    });
}

bool ProcessMonitor::web_context(std::uint32_t uid) {
    passwd* user = getpwuid(uid);
    if (!user || !user->pw_name) return false;
    const std::string name = user->pw_name;
    return name == "www-data" || name == "nginx" || name == "apache2" || name == "apache";
}

void ProcessMonitor::inspect(const EbpfMonitor::ExecEvent& event) {
    if (!running_ || !web_context(event.uid) || !suspicious_binary(event.filename)) return;
    const bool killed = kill(static_cast<pid_t>(event.pid), SIGKILL) == 0;
    if (killed) blocked_.fetch_add(1);
    Logger::get_instance().log(LogLevel::ERR, "CRITICAL_REVERSE_SHELL",
        "Blocked suspicious executable from web context: " + event.filename + " pid=" + std::to_string(event.pid),
        "CRITICAL", killed ? "SIGKILL" : "alerted", "", "process-monitor", "Web-shell execution", 1, 0,
        "Execution", "TA0002", "T1059", "Command and Scripting Interpreter", "",
        "sys_enter_execve", event.filename, "endpoint");
    SiemExporter::instance().export_event("CRITICAL_REVERSE_SHELL", "Blocked web-context executable", 10,
        "", killed ? "SIGKILL" : "ALERT", "pid=" + std::to_string(event.pid) + " binary=" + event.filename);
}

} // namespace copsec
