#include "anomaly_engine.hpp"
#include "penalty_engine.hpp"
#include "shm_ipc.hpp"
#include "siem_exporter.hpp"

#include <cmath>
#include <unordered_map>

namespace copsec {

AnomalyEngine::AnomalyEngine(PenaltyEngine& penalty_engine, ShmServer& shm_server)
    : penalty_engine_(penalty_engine), shm_server_(shm_server) {}

double AnomalyEngine::shannon_entropy(const std::string& value) {
    if (value.empty()) return 0.0;
    std::unordered_map<unsigned char, std::size_t> frequencies;
    for (const unsigned char character : value) ++frequencies[character];
    double entropy = 0.0;
    for (const auto& [character, count] : frequencies) {
        (void)character;
        const double probability = static_cast<double>(count) / value.size();
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

void AnomalyEngine::evaluate_http(const std::string& ip, const std::string& payload,
                                  const std::string& raw_line) {
    if (ip.empty()) return;
    const double entropy = shannon_entropy(payload);
    if (payload.size() > 20 && entropy > 4.5) {
        penalty_engine_.record(ip, 30, "obfuscated-payload", raw_line);
        SiemExporter::instance().export_event("OBFUSCATED_PAYLOAD", "High entropy HTTP payload", 7,
            ip, "SCORE", "mitre=T1027 (Obfuscated Files or Information) entropy=" + std::to_string(entropy));
    }

    if (raw_line.find(" 404 ") == std::string::npos && raw_line.find(" 403 ") == std::string::npos) return;
    const auto now = Clock::now();
    std::size_t count = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& window = response_windows_[ip].responses;
        while (!window.empty() && now - window.front() > std::chrono::seconds(10)) window.pop_front();
        window.push_back(now);
        count = window.size();
    }
    if (count == 16) {
        penalty_engine_.record(ip, 40, "recon-scanner", raw_line);
        SiemExporter::instance().export_event("RECON_SCANNER", "Excessive HTTP 404/403 responses", 8,
            ip, "SCORE", "mitre=T1595.002 (Vulnerability Scanning) responses_10s=" + std::to_string(count));
    }
}

} // namespace copsec
