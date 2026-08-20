#pragma once

#include <cmath>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace copsec {

class AnomalyDetector {
public:
    explicit AnomalyDetector(double alpha = 0.2, std::size_t window_size = 64)
        : m_alpha(alpha), m_window_size(window_size) {}

    void update(const std::string& key, double value) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto& entry = m_series[key];
        entry.values.push_back(value);
        if (entry.values.size() > m_window_size) {
            entry.values.pop_front();
        }

        if (entry.ema == 0.0) {
            entry.ema = value;
        } else {
            entry.ema = m_alpha * value + (1.0 - m_alpha) * entry.ema;
        }
    }

    bool is_anomalous(const std::string& key, double value, double sigma_threshold = 3.0) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_series.find(key);
        if (it == m_series.end() || it->second.values.size() < 3) {
            return false;
        }

        const auto& values = it->second.values;
        double mean = 0.0;
        for (double v : values) {
            mean += v;
        }
        mean /= static_cast<double>(values.size());

        double variance = 0.0;
        for (double v : values) {
            const double diff = v - mean;
            variance += diff * diff;
        }
        variance /= static_cast<double>(values.size() - 1);

        const double stddev = std::sqrt(variance);
        if (stddev < 1e-9) {
            return false;
        }

        const double zscore = std::fabs(value - mean) / stddev;
        return zscore > sigma_threshold;
    }

private:
    struct SeriesState {
        std::deque<double> values;
        double ema = 0.0;
    };

    mutable std::mutex m_mutex;
    double m_alpha;
    std::size_t m_window_size;
    std::unordered_map<std::string, SeriesState> m_series;
};

} // namespace copsec
