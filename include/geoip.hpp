#ifndef COPSEC_GEOIP_HPP
#define COPSEC_GEOIP_HPP

#include <string>
#include <maxminddb.h>

namespace copsec {

struct GeoIPResult {
    std::string country_code = "XX";
    std::string country_name = "Unknown";
    uint32_t asn = 0;
    std::string org = "Unknown";
};

class GeoIPLookup {
public:
    GeoIPResult lookup(const std::string& ip_address) const {
        GeoIPResult result;
        MMDB_s city_db;
        int status = MMDB_open("/var/lib/GeoIP/GeoLite2-City.mmdb", MMDB_MODE_MMAP, &city_db);
        if (status == MMDB_SUCCESS) {
            int gai_error = 0;
            int mmdb_error = 0;
            MMDB_lookup_result_s city_result = MMDB_lookup_string(&city_db, ip_address.c_str(), &gai_error, &mmdb_error);
            if (city_result.found_entry) {
                MMDB_entry_data_s entry;
                if (MMDB_get_value(&city_result.entry, &entry, "country", "iso_code", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    result.country_code = std::string(entry.utf8_string, entry.data_size);
                }
                if (MMDB_get_value(&city_result.entry, &entry, "country", "names", "en", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    result.country_name = std::string(entry.utf8_string, entry.data_size);
                }
            }
            MMDB_close(&city_db);
        }

        MMDB_s asn_db;
        status = MMDB_open("/var/lib/GeoIP/GeoLite2-ASN.mmdb", MMDB_MODE_MMAP, &asn_db);
        if (status == MMDB_SUCCESS) {
            int gai_error = 0;
            int mmdb_error = 0;
            MMDB_lookup_result_s asn_result = MMDB_lookup_string(&asn_db, ip_address.c_str(), &gai_error, &mmdb_error);
            if (asn_result.found_entry) {
                MMDB_entry_data_s entry;
                if (MMDB_get_value(&asn_result.entry, &entry, "autonomous_system_number", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UINT32) {
                    result.asn = entry.uint32;
                }
                if (MMDB_get_value(&asn_result.entry, &entry, "autonomous_system_organization", nullptr) == MMDB_SUCCESS && entry.has_data && entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    result.org = std::string(entry.utf8_string, entry.data_size);
                }
            }
            MMDB_close(&asn_db);
        }

        return result;
    }
};

} // namespace copsec

#endif // COPSEC_GEOIP_HPP
