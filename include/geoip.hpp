#pragma once

#include <cstdint>
#include <string>

#if defined(__has_include)
#  if __has_include(<maxminddb.h>)
#    include <maxminddb.h>
#    define COPSEC_HAS_MAXMINDDB 1
#  else
#    define COPSEC_HAS_MAXMINDDB 0
#  endif
#else
#  define COPSEC_HAS_MAXMINDDB 0
#endif

namespace copsec {

struct GeoIPResult {
    std::string country_code = "ZZ";
    std::string asn_name = "unknown";
    std::uint32_t asn = 0;
    bool available = false;
    std::string ip_address;
};

class GeoIPLookup {
public:
    GeoIPLookup(const std::string& city_db_path = "/etc/GeoIP2-City.mmdb",
                const std::string& asn_db_path = "/etc/GeoLite2-ASN.mmdb")
        : m_city_db_path(city_db_path), m_asn_db_path(asn_db_path) {}

    GeoIPResult lookup(const std::string& ip_address) const {
        GeoIPResult result;
        result.ip_address = ip_address;

#if COPSEC_HAS_MAXMINDDB
        MMDB_s city_db{};
        MMDB_s asn_db{};

        if (MMDB_open(m_city_db_path.c_str(), MMDB_MODE_MMAP, &city_db) == MMDB_SUCCESS) {
            int status = 0;
            MMDB_lookup_result_s city_result = MMDB_lookup_string(&city_db, ip_address.c_str(), &status);
            if (status == MMDB_SUCCESS && city_result.found_entry) {
                int gai_error = 0;
                int mmdb_error = 0;
                MMDB_entry_data_s entry{};
                if (MMDB_get_value(&city_result, &entry, "country", "iso_code", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    std::string code(entry.utf8_string, entry.data_size);
                    result.country_code = code;
                    result.available = true;
                }
                MMDB_get_value(&city_result, &entry, "country", "names", "en", nullptr);
                if (entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    std::string name(entry.utf8_string, entry.data_size);
                    if (!name.empty()) {
                        result.country_code = name.substr(0, 2);
                    }
                }
                MMDB_free(&city_db);
            }
        }

        if (MMDB_open(m_asn_db_path.c_str(), MMDB_MODE_MMAP, &asn_db) == MMDB_SUCCESS) {
            int status = 0;
            MMDB_lookup_result_s asn_result = MMDB_lookup_string(&asn_db, ip_address.c_str(), &status);
            if (status == MMDB_SUCCESS && asn_result.found_entry) {
                MMDB_entry_data_s entry{};
                if (MMDB_get_value(&asn_result, &entry, "autonomous_system_number", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UINT32) {
                    result.asn = static_cast<std::uint32_t>(entry.uint32);
                    result.available = true;
                }
                if (MMDB_get_value(&asn_result, &entry, "autonomous_system_organization", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    std::string name(entry.utf8_string, entry.data_size);
                    if (!name.empty()) {
                        result.asn_name = name;
                    }
                }
                MMDB_free(&asn_db);
            }
        }

        if (!result.available && !ip_address.empty()) {
            result.country_code = "ZZ";
            result.asn_name = "unknown";
            result.asn = 0;
        }
#else
        (void)m_city_db_path;
        (void)m_asn_db_path;
#endif

        return result;
    }

private:
    std::string m_city_db_path;
    std::string m_asn_db_path;
};

} // namespace copsec
