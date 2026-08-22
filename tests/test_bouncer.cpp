#include <gtest/gtest.h>
#include "whitelist.hpp"
#include "db_manager.hpp"

TEST(WhitelistFastPathTest, LoopbackIPv4) {
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("127.0.0.1"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("127.0.0.2"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("127.255.255.254"));
}

TEST(WhitelistFastPathTest, LoopbackIPv6) {
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("::1"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("localhost"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("::ffff:127.0.0.1"));
}

TEST(WhitelistFastPathTest, TailscaleRange) {
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("100.64.0.1"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("100.100.100.100"));
    EXPECT_TRUE(WhitelistManager::is_fast_path_builtin("100.127.255.254"));
    EXPECT_FALSE(WhitelistManager::is_fast_path_builtin("100.128.0.1"));
}

TEST(WhitelistFastPathTest, ExternalUntrustedIP) {
    EXPECT_FALSE(WhitelistManager::is_fast_path_builtin("198.51.100.23"));
    EXPECT_FALSE(WhitelistManager::is_fast_path_builtin("203.0.113.45"));
}

TEST(WhitelistConfigTest, LoadJsonConfig) {
    WhitelistManager wm;
    EXPECT_TRUE(wm.load_whitelist("/home/copdasten/Documents/CoPSeC/copsec/config/whitelist.json"));
    EXPECT_TRUE(wm.is_whitelisted("127.0.0.1"));
    EXPECT_TRUE(wm.is_whitelisted("10.0.5.10"));
    EXPECT_TRUE(wm.is_whitelisted("192.168.1.100"));
    EXPECT_TRUE(wm.is_whitelisted("100.64.5.1"));
    EXPECT_FALSE(wm.is_whitelisted("185.220.101.5"));
}
