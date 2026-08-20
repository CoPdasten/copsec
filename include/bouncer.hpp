#ifndef BOUNCER_HPP
#define BOUNCER_HPP

#include <string>
#include <mutex>
#include <cstdint>
#include <functional>
#include <vector>

struct nft_ctx;

namespace copsec {

class Bouncer {
public:
    struct BanInfo {
        std::string ip;
        std::string rule_id;
        int64_t expires_at = 0;
    };

    Bouncer();
    ~Bouncer();

    bool init_nftables();
    bool ban_ip(const std::string& ip, int duration_sec, const std::string& rule_id = "");
    bool bulk_ban_ips(const std::vector<std::string>& ips, int duration_sec, const std::string& rule_id = "");
    void set_ban_observer(std::function<void(const std::string&, int, const std::string&)> observer);
    bool unban_ip(const std::string& ip);
    std::vector<BanInfo> active_bans() const;

private:
    bool execute_command(const std::string& cmd);
    bool run_libnftables(const std::string& cmd);
    bool run_shell_fallback(const std::string& cmd);

    struct nft_ctx* m_nft_ctx;
    mutable std::mutex m_mutex;
    std::vector<BanInfo> m_bans;
    std::function<void(const std::string&, int, const std::string&)> m_ban_observer;
};

} // namespace copsec

#endif // BOUNCER_HPP