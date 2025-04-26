#include <iostream> 
#include <fstream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>

// ========== SHA256 IMPLEMENTACE ==========
#include <cstring>
#include <cstdint>



namespace fs = std::filesystem;


// Functions for SHA256
uint32_t rotr(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

uint32_t bswap32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x000000FF) << 24);
}

uint64_t bswap64(uint64_t x) {
    return ((x & 0xFF00000000000000ull) >> 56) |
        ((x & 0x00FF000000000000ull) >> 40) |
        ((x & 0x0000FF0000000000ull) >> 24) |
        ((x & 0x000000FF00000000ull) >> 8) |
        ((x & 0x00000000FF000000ull) << 8) |
        ((x & 0x0000000000FF0000ull) << 24) |
        ((x & 0x000000000000FF00ull) << 40) |
        ((x & 0x00000000000000FFull) << 56);
}

// SHA256 Class for calculating SHA256 hash
class SHA256 {
public:
    static std::string hashFile(const std::string& path) {
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        uint8_t buffer[64] = { 0 };
        uint64_t bitlen = 0;
        uint8_t hash[32] = { 0 };

        std::ifstream file(path, std::ios::binary);
        if (!file) return "";

        while (file) {
            file.read(reinterpret_cast<char*>(buffer), 64);
            std::streamsize read = file.gcount();
            bitlen += read * 8;
            if (read == 64)
                transform(buffer, state);
            else {
                memset(buffer + read, 0, 64 - read);
                buffer[read] = 0x80;
                if (read >= 56) {
                    transform(buffer, state);
                    memset(buffer, 0, 64);
                }
                uint64_t bitlen_be = bswap64(bitlen);
                memcpy(buffer + 56, &bitlen_be, 8);
                transform(buffer, state);
            }
        }

        for (int i = 0; i < 8; i++) {
            state[i] = bswap32(state[i]);
            memcpy(hash + i * 4, &state[i], 4);
        }

        return toHex(hash);
    }

private:
    static std::string toHex(const uint8_t* hash) {
        std::ostringstream oss;
        for (int i = 0; i < 32; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return oss.str();
    }

    static void transform(const uint8_t* data, uint32_t* state) {
        const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t a, b, c, d, e, f, g, h, t1, t2;
        uint32_t m[64] = { 0 };

        for (int i = 0; i < 16; ++i)
            m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
            (data[i * 4 + 2] << 8) | data[i * 4 + 3];

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            t1 = h + S1 + ch + K[i] + m[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = S0 + maj;

            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
};



// ========== Load .bav database ==========
std::unordered_map<std::string, std::string> loadDatabase(const std::string& dbPath) {
    std::unordered_map<std::string, std::string> db;
    std::ifstream dbFile(dbPath);
    std::string line;

    while (std::getline(dbFile, line)) {
        if (line.empty() || line[0] == ':') continue; // empty lines and comments

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string hash = line.substr(0, colon);
            std::string name = line.substr(colon + 1);
            db[hash] = name;
        }
    }

    return db;
}


std::atomic<int> totalScanned(0);
std::atomic<int> cleanCount(0);
std::atomic<int> infectedCount(0);




// Function for scanning files
void scanFile(const std::string& path, const bool& showCleanStatus) {
    if (!fs::exists(path)) {
        std::cout << "[-] File not found: " << path << std::endl;
        return;
    }

    std::cout << "Scanning file: " << path << std::endl;
    std::string fileHash = SHA256::hashFile(path);
    std::cout << "SHA256: " << fileHash << std::endl;

    auto db = loadDatabase("VirusDataBaseHash.bav");


    auto it = db.find(fileHash);
    if (it != db.end()) {
        std::cout << "Infected: " << it->second << std::endl;
        std::cout << std::endl;
    }
    else {
        if (showCleanStatus) {
            std::cout << "Clean" << std::endl;
            std::cout << std::endl;
        }
    }
}


std::mutex coutMutex;
std::mutex queueMutex;
std::queue<std::string> filesQueue;
bool showCleanStatus = true;  // default true

void workerThread(const std::unordered_map<std::string, std::string>& db) {
    while (true) {
        std::string file;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (filesQueue.empty()) return;
            file = filesQueue.front();
            filesQueue.pop();
        }

        ++totalScanned;

        std::string fileHash = SHA256::hashFile(file);

        auto it = db.find(fileHash);
        if (it != db.end()) {
            ++infectedCount;
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "Infected: " << file << " : " << it->second << std::endl;
            }
        }
        else {
            ++cleanCount;
            if (showCleanStatus) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "Clean: " << file << std::endl;
            }
        }
    }
}

void scanDirectory(const std::string& path) {
    if (!fs::exists(path)) {
        std::cout << "Directory does not exist!" << std::endl;
        return;
    }

    if (!fs::is_directory(path)) {
        std::cout << "The provided path is not a directory!" << std::endl;
        return;
    }

    std::cout << "Indexing files..." << std::endl;

    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(entry.status())) {
            std::lock_guard<std::mutex> lock(queueMutex);
            filesQueue.push(entry.path().string());
        }
    }

    std::cout << "Files found: " << filesQueue.size() << std::endl;

    const int threadCount = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    auto db = loadDatabase("VirusDataBaseHash.bav");

    std::cout << "Using " << threadCount << " threads..." << std::endl;

    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back(workerThread, std::ref(db));
    }

    for (auto& t : threads) {
        t.join();
    }

    // Statistics
    std::cout << "Finished scanning directory: " << path << std::endl;
    std::cout << std::endl;
    std::cout << "Total files scanned:   " << totalScanned.load() <<
        "   Clean files:   " << cleanCount.load() <<
        "   Infected files:   " << infectedCount.load() << std::endl;
}


// Function for scanning disks
void scanDisc(const std::string& disc) {
    std::cout << "[DEBUG] Scanning disk: " << disc << std::endl;
}

void scanAll() {
    std::cout << "[DEBUG] Scanning all disks..." << std::endl;
}

void showMenu() {
    std::cout << std::endl;
    std::cout << "==============================  C++ Antivirus  ==============================" << std::endl;
    std::cout << "                                                       Developed by Kecalek13" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "[1] Scan File" << std::endl;
    std::cout << "[2] Scan Directory" << std::endl;
    std::cout << "[3] Scan Disc" << std::endl;
    std::cout << "[4] Scan All" << std::endl;
    std::cout << std::endl;
    std::cout << "[99] Exit" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
}

int main() {
    int choice;
    std::string path;

    while (true) {
        showMenu();

        std::cout << "Choose option: ";
        std::cin >> choice;
        std::cout << std::endl;

        switch (choice) {
        case 1:
            std::cout << std::endl;
            std::cout << "Path to file: ";
            std::cin >> path;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            scanFile(path, true);

            break;
        case 2:
            std::cout << std::endl;
            std::cout << "Path to directory: ";
            std::cin >> path;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            scanDirectory(path);

            break;
        case 3:
            std::cout << std::endl;
            std::cout << "Disk to scan (example: C:): ";
            std::cin >> path;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            scanDisc(path);

            break;
        case 4:
            std::cout << std::endl;

            scanAll();

            break;
        case 99:
            std::cout << std::endl;
            std::cout << "Goodbye!!!";
            std::cin.get();
            return 0;
        default:
            std::cout << "Invalid option !" << std::endl;
            break;
        }
    }

    std::cout << "Goodbye!!!" << std::endl;
    std::cin.get();
    return 0;
}