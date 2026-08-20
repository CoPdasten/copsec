#ifndef NORMALIZER_HPP
#define NORMALIZER_HPP

#include <string>
#include <algorithm>
#include <cctype>

class Normalizer {
public:
    static std::string normalize(const std::string& raw_line) {
        std::string decoded = url_decode(raw_line);
        std::string previous;
        int depth = 0;
        
        // Multi-stage / Double encoding decode
        while (decoded != previous && depth < 3) {
            previous = decoded;
            decoded = url_decode(decoded);
            depth++;
        }

        // Lowercase normalization
        std::transform(decoded.begin(), decoded.end(), decoded.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        return decoded;
    }

private:
    static std::string url_decode(const std::string& in) {
        std::string out;
        out.reserve(in.size());
        for (std::size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%') {
                if (i + 2 < in.size()) {
                    std::string hex_str = in.substr(i + 1, 2);
                    try {
                        int hex_val = std::stoi(hex_str, nullptr, 16);
                        out += static_cast<char>(hex_val);
                        i += 2;
                    } catch (...) {
                        out += in[i];
                    }
                } else {
                    out += in[i];
                }
            } else if (in[i] == '+') {
                out += ' ';
            } else {
                out += in[i];
            }
        }
        return out;
    }
};

#endif // NORMALIZER_HPP