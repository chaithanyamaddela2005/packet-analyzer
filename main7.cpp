#include "crow.h"
#include <nlohmann/json.hpp>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <map>
#include <algorithm>
#include <thread>
#include <mutex>
#include <queue>
#include <memory>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <mysql/mysql.h>
#include <atomic>
#include <csignal>
#include <future>

using namespace std;
using json = nlohmann::json;

// ===================== DATABASE CONFIGURATION =====================
struct DBConfig {
    string host = "localhost";
    string user = "root";
    string password = "ROOT";
    string database = "project";
    int port = 3306;
};

// ===================== DATABASE CONNECTION CLASS =====================
class DatabaseConnection {
private:
    MYSQL* conn;
    DBConfig config;
    mutex dbMutex;
    
public:
    DatabaseConnection(const DBConfig& cfg) : config(cfg), conn(nullptr) {}
    
    ~DatabaseConnection() {
        disconnect();
    }
    
    bool connect() {
        lock_guard<mutex> lock(dbMutex);
        
        conn = mysql_init(nullptr);
        if (!conn) {
            cerr << "✖ MySQL initialization failed" << endl;
            return false;
        }
        
        my_bool reconnect = 1;
        mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect);
        
        if (!mysql_real_connect(conn, config.host.c_str(), config.user.c_str(),
                                config.password.c_str(), config.database.c_str(),
                                config.port, nullptr, 0)) {
            cerr << "✖ MySQL connection failed: " << mysql_error(conn) << endl;
            mysql_close(conn);
            conn = nullptr;
            return false;
        }
        
        cout << "✓ Connected to MySQL database: " << config.database << endl;
        return true;
    }
    
    void disconnect() {
        lock_guard<mutex> lock(dbMutex);
        if (conn) {
            mysql_close(conn);
            conn = nullptr;
        }
    }
    
    bool executeQuery(const string& query) {
        lock_guard<mutex> lock(dbMutex);
        
        if (!conn) {
            cerr << "✖ Database connection lost" << endl;
            return false;
        }
        
        if (mysql_query(conn, query.c_str())) {
            cerr << "✖ Query failed: " << mysql_error(conn) << endl;
            return false;
        }
        
        return true;
    }
    
    bool isConnected() {
        lock_guard<mutex> lock(dbMutex);
        if (!conn) return false;
        return mysql_ping(conn) == 0;
    }
    
    string escapeString(const string& str) {
        lock_guard<mutex> lock(dbMutex);
        
        if (!conn) return str;
        
        char* escaped = new char[str.length() * 2 + 1];
        mysql_real_escape_string(conn, escaped, str.c_str(), str.length());
        string result(escaped);
        delete[] escaped;
        return result;
    }
    
    MYSQL* getConnection() {
        return conn;
    }
    
    mutex& getMutex() {
        return dbMutex;
    }
    
    // NEW: Create a session and return session_id
    int createSession(const string& sessionName, const string& filePath) {
        lock_guard<mutex> lock(dbMutex);
        
        if (!conn) {
            cerr << "✖ Database not connected" << endl;
            return -1;
        }
        
        // Escape strings manually since we have the connection
        char* escName = new char[sessionName.length() * 2 + 1];
        char* escPath = new char[filePath.length() * 2 + 1];
        mysql_real_escape_string(conn, escName, sessionName.c_str(), sessionName.length());
        mysql_real_escape_string(conn, escPath, filePath.c_str(), filePath.length());
        
        char query[1024];
        snprintf(query, sizeof(query),
                 "INSERT INTO pcap_sessions (session_name, file_path) VALUES ('%s', '%s')",
                 escName, escPath);
        
        delete[] escName;
        delete[] escPath;
        
        if (mysql_query(conn, query)) {
            cerr << "✖ Failed to create session: " << mysql_error(conn) << endl;
            return -1;
        }
        
        // Get the inserted ID (this is the primary key 'id', which is what foreign keys reference)
        int sessionId = (int)mysql_insert_id(conn);
        
        if (sessionId <= 0) {
            cerr << "✖ Failed to retrieve session ID" << endl;
            return -1;
        }
        
        cout << "✓ Created session with ID: " << sessionId << endl;
        return sessionId;
    }
    
    // NEW: Get all sessions
    json getSessions() {
        lock_guard<mutex> lock(dbMutex);
        json sessions = json::array();
        
        if (!conn) {
            cerr << "✖ Database not connected" << endl;
            return sessions;
        }
        
        const char* query = "SELECT id, session_name, file_path, upload_time FROM pcap_sessions ORDER BY id DESC";
        
        if (mysql_query(conn, query)) {
            cerr << "✖ Failed to fetch sessions: " << mysql_error(conn) << endl;
            return sessions;
        }
        
        MYSQL_RES* result = mysql_store_result(conn);
        if (!result) {
            cerr << "✖ Failed to store result: " << mysql_error(conn) << endl;
            return sessions;
        }
        
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(result))) {
            json session;
            session["id"] = row[0] ? atoi(row[0]) : 0;
            session["session_name"] = row[1] ? row[1] : "";
            session["file_path"] = row[2] ? row[2] : "";
            session["upload_time"] = row[3] ? row[3] : "";
            sessions.push_back(session);
        }
        
        mysql_free_result(result);
        cout << "✓ Retrieved " << sessions.size() << " sessions" << endl;
        return sessions;
    }
    
    // NEW: Get session data by ID
    json getSessionData(int sessionId) {
        lock_guard<mutex> lock(dbMutex);
        json data;
        data["packets"] = json::array();
        data["ip_stats"] = json::array();
        data["protocol_stats"] = json::array();
        
        if (!conn) {
            cerr << "✖ Database not connected" << endl;
            data["error"] = "Database not connected";
            return data;
        }
        
        // Fetch packets
        char query[512];
        snprintf(query, sizeof(query),
                 "SELECT id, timestamp, src_ip, dest_ip, src_port, dest_port, "
                 "l4_protocol, app_protocol, length, summary FROM packets WHERE session_id = %d ORDER BY id",
                 sessionId);
        
        if (mysql_query(conn, query)) {
            cerr << "✖ Failed to fetch packets: " << mysql_error(conn) << endl;
            data["error"] = mysql_error(conn);
            return data;
        }
        
        MYSQL_RES* result = mysql_store_result(conn);
        if (result) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(result))) {
                json packet;
                packet["number"] = row[0] ? atoi(row[0]) : 0;
                packet["timestamp"] = row[1] ? row[1] : "";
                
                string srcIP = row[2] ? row[2] : "";
                string destIP = row[3] ? row[3] : "";
                int srcPort = row[4] ? atoi(row[4]) : 0;
                int destPort = row[5] ? atoi(row[5]) : 0;
                
                packet["source"] = srcIP + (srcPort > 0 ? ":" + to_string(srcPort) : "");
                packet["destination"] = destIP + (destPort > 0 ? ":" + to_string(destPort) : "");
                packet["protocol"] = row[6] ? row[6] : "";
                packet["app_protocol"] = row[7] ? row[7] : "";
                packet["length"] = row[8] ? atoi(row[8]) : 0;
                packet["summary"] = row[9] ? row[9] : "";
                
                data["packets"].push_back(packet);
            }
            mysql_free_result(result);
        }
        
        // Fetch IP stats
        snprintf(query, sizeof(query),
                 "SELECT ip, type, packet_count FROM ip_stats WHERE session_id = %d",
                 sessionId);
        
        if (mysql_query(conn, query) == 0) {
            result = mysql_store_result(conn);
            if (result) {
                MYSQL_ROW row;
                while ((row = mysql_fetch_row(result))) {
                    json stat;
                    stat["ip"] = row[0] ? row[0] : "";
                    stat["type"] = row[1] ? row[1] : "";
                    stat["packet_count"] = row[2] ? atoi(row[2]) : 0;
                    data["ip_stats"].push_back(stat);
                }
                mysql_free_result(result);
            }
        }
        
        // Fetch protocol stats
        snprintf(query, sizeof(query),
                 "SELECT protocol_name, count FROM protocol_stats WHERE session_id = %d",
                 sessionId);
        
        if (mysql_query(conn, query) == 0) {
            result = mysql_store_result(conn);
            if (result) {
                MYSQL_ROW row;
                while ((row = mysql_fetch_row(result))) {
                    json stat;
                    stat["protocol_name"] = row[0] ? row[0] : "";
                    stat["count"] = row[1] ? atoi(row[1]) : 0;
                    data["protocol_stats"].push_back(stat);
                }
                mysql_free_result(result);
            }
        }
        
        cout << "✓ Retrieved session data for session_id: " << sessionId << endl;
        return data;
    }
};

// ===================== PACKET BATCH INSERTER =====================
class PacketBatchInserter {
private:
    DatabaseConnection& db;
    vector<tuple<int, long long, string, string, int, int, string, string, int, string>> batchData;
    mutex batchMutex;
    const size_t BATCH_SIZE = 100;
    
public:
    PacketBatchInserter(DatabaseConnection& database) : db(database) {}
    
    void addPacket(int sessionId, long long timestamp, const string& srcIP, const string& destIP,
                   int srcPort, int destPort, const string& l4Proto, 
                   const string& appProto, int length, const string& summary) {
        
        lock_guard<mutex> lock(batchMutex);
        
        batchData.push_back(make_tuple(sessionId, timestamp, srcIP, destIP, srcPort, destPort, 
                                       l4Proto, appProto, length, summary));
        
        if (batchData.size() >= BATCH_SIZE) {
            flush();
        }
    }
    
    void flush() {
        if (batchData.empty()) return;
        
        try {
            lock_guard<mutex> dbLock(db.getMutex());
            MYSQL* conn = db.getConnection();
            if (!conn) return;
            
            string query = "INSERT INTO packets (session_id, timestamp, src_ip, dest_ip, src_port, dest_port, "
                          "l4_protocol, app_protocol, length, summary) VALUES ";
            
            for (size_t i = 0; i < batchData.size(); i++) {
                const auto& data = batchData[i];
                
                char buffer[2048];
                string summaryStr = get<9>(data);
                string escapedSummary;
                if (conn) {
                    escapedSummary.resize(summaryStr.size() * 2 + 1);
                    unsigned long newLen = mysql_real_escape_string(conn, &escapedSummary[0], summaryStr.c_str(), summaryStr.size());
                    escapedSummary.resize(newLen);
                } else {
                    escapedSummary = summaryStr;
                }
                
                snprintf(buffer, sizeof(buffer),
                         "(%d, %lld, '%s', '%s', %d, %d, '%s', '%s', %d, '%s')",
                         get<0>(data), get<1>(data), get<2>(data).c_str(), get<3>(data).c_str(),
                         get<4>(data), get<5>(data), get<6>(data).c_str(),
                         get<7>(data).c_str(), get<8>(data), escapedSummary.c_str());
                
                query += buffer;
                if (i < batchData.size() - 1) query += ", ";
            }
            
            if (mysql_query(conn, query.c_str())) {
                cerr << "✖ Batch insert failed: " << mysql_error(conn) << endl;
            } else {
                cout << "✓ Inserted batch of " << batchData.size() << " packets" << endl;
            }
            
            batchData.clear();
            
        } catch (const exception& e) {
            cerr << "✖ Batch insert exception: " << e.what() << endl;
            batchData.clear();
        }
    }
    
    ~PacketBatchInserter() {
        lock_guard<mutex> lock(batchMutex);
    }
};

// ===================== STATISTICS UPDATER =====================
class StatsUpdater {
private:
    DatabaseConnection& db;
    int sessionId;
    map<string, int> sourceIPCounts;
    map<string, int> destIPCounts;
    map<string, int> protocolCounts;
    mutex statsMutex;
    
public:
    StatsUpdater(DatabaseConnection& database, int sessId) : db(database), sessionId(sessId) {}
    
    void addSourceIP(const string& ip) {
        lock_guard<mutex> lock(statsMutex);
        sourceIPCounts[ip]++;
    }
    
    void addDestIP(const string& ip) {
        lock_guard<mutex> lock(statsMutex);
        destIPCounts[ip]++;
    }
    
    void addProtocol(const string& protocol) {
        lock_guard<mutex> lock(statsMutex);
        protocolCounts[protocol]++;
    }
    
    void updateDatabase() {
        lock_guard<mutex> lock(statsMutex);
        lock_guard<mutex> dbLock(db.getMutex());
        
        MYSQL* conn = db.getConnection();
        if (!conn) return;
        
        try {
            cout << "✓ Updating IP statistics..." << endl;
            
            for (const auto& [ip, count] : sourceIPCounts) {
                char query[512];
                snprintf(query, sizeof(query),
                         "INSERT INTO ip_stats (session_id, ip, type, packet_count) VALUES (%d, '%s', 'SOURCE', %d) "
                         "ON DUPLICATE KEY UPDATE packet_count = packet_count + %d",
                         sessionId, ip.c_str(), count, count);
                
                if (mysql_query(conn, query)) {
                    cerr << "✖ Source IP update failed: " << mysql_error(conn) << endl;
                }
            }
            
            for (const auto& [ip, count] : destIPCounts) {
                char query[512];
                snprintf(query, sizeof(query),
                         "INSERT INTO ip_stats (session_id, ip, type, packet_count) VALUES (%d, '%s', 'DEST', %d) "
                         "ON DUPLICATE KEY UPDATE packet_count = packet_count + %d",
                         sessionId, ip.c_str(), count, count);
                
                if (mysql_query(conn, query)) {
                    cerr << "✖ Dest IP update failed: " << mysql_error(conn) << endl;
                }
            }
            
            cout << "✓ Updating protocol statistics..." << endl;
            
            for (const auto& [protocol, count] : protocolCounts) {
                char query[512];
                snprintf(query, sizeof(query),
                         "INSERT INTO protocol_stats (session_id, protocol_name, count) VALUES (%d, '%s', %d) "
                         "ON DUPLICATE KEY UPDATE count = count + %d",
                         sessionId, protocol.c_str(), count, count);
                
                if (mysql_query(conn, query)) {
                    cerr << "✖ Protocol update failed: " << mysql_error(conn) << endl;
                }
            }
            
            cout << "✓ Database statistics updated successfully" << endl;
            
        } catch (const exception& e) {
            cerr << "✖ Stats update exception: " << e.what() << endl;
        }
    }
};

// ===================== PACKET CLASS =====================
class Packet {
public:
    int id;
    string timestamp;
    string srcIP;
    string destIP;
    int srcPort;
    int destPort;
    string l4Protocol;
    string appProtocol;
    string summary;
    int length;
    
    json to_json() const {
        return json{
            {"number", id},
            {"source", srcIP + (srcPort > 0 ? ":" + to_string(srcPort) : "")},
            {"destination", destIP + (destPort > 0 ? ":" + to_string(destPort) : "")},
            {"protocol", l4Protocol},
            {"app_protocol", appProtocol},
            {"length", length},
            {"summary", summary},
            {"timestamp", timestamp}
        };
    }
};

// ===================== PROTOCOL PARSERS =====================
class ProtocolParser {
public:
    virtual bool canParse(const Packet& pkt) const = 0;
    virtual void parse(Packet& pkt) = 0;
    virtual ~ProtocolParser() {}
};

class HTTPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "TCP" && 
                (pkt.destPort == 80 || pkt.srcPort == 80 || pkt.destPort == 8080 || pkt.srcPort == 8080));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "HTTP";
        pkt.summary = string("HTTP ") + (pkt.destPort == 80 || pkt.destPort == 8080 ? "request" : "response");
    }
};

class HTTPSParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "TCP" && (pkt.destPort == 443 || pkt.srcPort == 443));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "HTTPS";
        pkt.summary = "HTTPS encrypted traffic";
    }
};

class DNSParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return ((pkt.l4Protocol == "UDP" || pkt.l4Protocol == "TCP") && 
                (pkt.destPort == 53 || pkt.srcPort == 53));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "DNS";
        pkt.summary = string("DNS ") + (pkt.destPort == 53 ? "query" : "response");
    }
};

class FTPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "TCP" && 
                (pkt.destPort == 21 || pkt.srcPort == 21 || pkt.destPort == 20 || pkt.srcPort == 20));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "FTP";
        pkt.summary = (pkt.destPort == 21 || pkt.srcPort == 21) ? "FTP control" : "FTP data";
    }
};

class SSHParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "TCP" && (pkt.destPort == 22 || pkt.srcPort == 22));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "SSH";
        pkt.summary = "SSH secure shell";
    }
};

class SMTPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "TCP" && 
                (pkt.destPort == 25 || pkt.srcPort == 25 || pkt.destPort == 587 || pkt.srcPort == 587));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "SMTP";
        pkt.summary = "SMTP mail transfer";
    }
};

class DHCPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return (pkt.l4Protocol == "UDP" && 
                (pkt.destPort == 67 || pkt.destPort == 68 || pkt.srcPort == 67 || pkt.srcPort == 68));
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "DHCP";
        pkt.summary = string("DHCP ") + (pkt.destPort == 67 ? "request" : "response");
    }
};

class ICMPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return pkt.l4Protocol == "ICMP";
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "ICMP";
        pkt.summary = "ICMP packet";
    }
};

class ARPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return pkt.l4Protocol == "ARP";
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "ARP";
        pkt.summary = "ARP address resolution";
    }
};

class GenericUDPParser : public ProtocolParser {
public:
    bool canParse(const Packet& pkt) const override {
        return pkt.l4Protocol == "UDP" && pkt.appProtocol.empty();
    }
    void parse(Packet& pkt) override {
        pkt.appProtocol = "UDP";
        pkt.summary = "Generic UDP traffic on port " + to_string(pkt.destPort);
    }
};

// ===================== STATISTICS CALCULATOR =====================
class StatsCalculator {
private:
    map<string, int> protocolCount;
    map<string, int> appProtocolCount;
    map<string, int> sourceIPCount;
    map<string, int> destIPCount;
    int totalBytes = 0;
    
public:
    void addPacket(const Packet& pkt) {
        protocolCount[pkt.l4Protocol]++;
        if (!pkt.appProtocol.empty()) {
            appProtocolCount[pkt.appProtocol]++;
        }
        sourceIPCount[pkt.srcIP]++;
        destIPCount[pkt.destIP]++;
        totalBytes += pkt.length;
    }
    
    json getStats(int totalPackets) {
        json stats;
        stats["TotalPackets"] = totalPackets;
        stats["TotalBytes"] = totalBytes;
        stats["UniqueSourceIPs"] = sourceIPCount.size();
        stats["UniqueDestIPs"] = destIPCount.size();
        
        json protocolDist = json::object();
        for (const auto& [protocol, count] : protocolCount) {
            protocolDist[protocol] = count;
        }
        stats["ProtocolDistribution"] = protocolDist;
        
        json appProtocolDist = json::object();
        for (const auto& [protocol, count] : appProtocolCount) {
            appProtocolDist[protocol] = count;
        }
        stats["AppProtocolDistribution"] = appProtocolDist;
        
        vector<pair<string, int>> topSources(sourceIPCount.begin(), sourceIPCount.end());
        sort(topSources.begin(), topSources.end(), 
             [](const pair<string,int>& a, const pair<string,int>& b) { return a.second > b.second; });
        
        json topSourcesJson = json::array();
        for (int i = 0; i < min(5, (int)topSources.size()); i++) {
            topSourcesJson.push_back({{"ip", topSources[i].first}, {"count", topSources[i].second}});
        }
        stats["TopSources"] = topSourcesJson;
        
        vector<pair<string, int>> topDests(destIPCount.begin(), destIPCount.end());
        sort(topDests.begin(), topDests.end(), 
             [](const pair<string,int>& a, const pair<string,int>& b) { return a.second > b.second; });
        
        json topDestsJson = json::array();
        for (int i = 0; i < min(5, (int)topDests.size()); i++) {
            topDestsJson.push_back({{"ip", topDests[i].first}, {"count", topDests[i].second}});
        }
        stats["TopDestinations"] = topDestsJson;
        
        return stats;
    }
};

// ===================== CANCELLATION + THREAD GLOBALS =====================
static std::atomic<bool> cancelAnalysis(false);

// ===================== PCAP ANALYZER WITH DATABASE =====================
json analyze_pcap(const string& filepath, DatabaseConnection& db, int sessionId, std::atomic<bool>& cancelFlag) {
    json result;
    result["success"] = false;
    result["packets"] = json::array();
    result["error"] = "";
    result["database_status"] = "disconnected";
    result["session_id"] = sessionId;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath.c_str(), errbuf);
    
    if (!handle) {
        result["error"] = string("Invalid PCAP format or corrupted file: ") + errbuf;
        cout << "ERROR: " << result["error"] << endl;
        return result;
    }

    cout << "✓ Analyzing PCAP file: " << filepath << endl;
    
    PacketBatchInserter batchInserter(db);
    StatsUpdater statsUpdater(db, sessionId);
    bool dbConnected = db.isConnected();
    
    if (dbConnected) {
        result["database_status"] = "connected";
        cout << "✓ Database connected - packets will be stored" << endl;
    } else {
        cout << "⚠ Database not connected - analysis will continue without storage" << endl;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int packetCount = 0;

    vector<ProtocolParser*> parsers = { 
        new HTTPParser(), new HTTPSParser(), new DNSParser(),
        new FTPParser(), new SSHParser(), new SMTPParser(),
        new DHCPParser(), new ICMPParser(), new ARPParser(),
        new GenericUDPParser()
    };
    
    vector<Packet> packets;
    StatsCalculator stats;

    while (pcap_next_ex(handle, &header, &data) >= 0) {
        if (cancelFlag.load()) {
            cout << "⚠ Analysis cancelled by request" << endl;
            break;
        }

        if (!header || !data) continue;

        Packet pkt;
        pkt.id = ++packetCount;
        pkt.timestamp = to_string(header->ts.tv_sec);
        pkt.length = header->len;
        pkt.srcPort = 0;
        pkt.destPort = 0;

        if (header->len < sizeof(struct ether_header)) continue;
        
        const struct ether_header* eth = (const struct ether_header*)data;
        u_short etherType = ntohs(eth->ether_type);

        if (etherType == ETHERTYPE_ARP) { 
            pkt.l4Protocol = "ARP";
            pkt.srcIP = "ARP";
            pkt.destIP = "ARP";
            pkt.appProtocol = "ARP";
            pkt.summary = "ARP packet";
            packets.push_back(pkt);
            stats.addPacket(pkt);
            
            if (dbConnected) {
                batchInserter.addPacket(sessionId, header->ts.tv_sec, pkt.srcIP, pkt.destIP,
                                       pkt.srcPort, pkt.destPort, pkt.l4Protocol,
                                       pkt.appProtocol, pkt.length, pkt.summary);
                statsUpdater.addProtocol(pkt.l4Protocol);
            }
            continue;
        }

        if (etherType == ETHERTYPE_IP) {
            if (header->len < sizeof(struct ether_header) + sizeof(struct ip)) continue;
            
            const struct ip* ipHeader = (const struct ip*)(data + sizeof(struct ether_header));
            
            char srcIPStr[INET_ADDRSTRLEN];
            char destIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHeader->ip_src), srcIPStr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIPStr, INET_ADDRSTRLEN);
            
            pkt.srcIP = string(srcIPStr);
            pkt.destIP = string(destIPStr);
            int ipHeaderLen = ipHeader->ip_hl * 4;
            
            if (ipHeader->ip_p == IPPROTO_TCP) {
                pkt.l4Protocol = "TCP";
                if (header->len >= sizeof(struct ether_header) + ipHeaderLen + sizeof(struct tcphdr)) {
                    const struct tcphdr* tcpHeader = (const struct tcphdr*)(data + sizeof(struct ether_header) + ipHeaderLen);
                    pkt.srcPort = ntohs(tcpHeader->th_sport);
                    pkt.destPort = ntohs(tcpHeader->th_dport);
                }
            } 
            else if (ipHeader->ip_p == IPPROTO_UDP) {
                pkt.l4Protocol = "UDP";
                if (header->len >= sizeof(struct ether_header) + ipHeaderLen + sizeof(struct udphdr)) {
                    const struct udphdr* udpHeader = (const struct udphdr*)(data + sizeof(struct ether_header) + ipHeaderLen);
                    pkt.srcPort = ntohs(udpHeader->uh_sport);
                    pkt.destPort = ntohs(udpHeader->uh_dport);
                }
            } 
            else if (ipHeader->ip_p == IPPROTO_ICMP) {
                pkt.l4Protocol = "ICMP";
                pkt.srcPort = pkt.destPort = 0;
            } 
            else {
                pkt.l4Protocol = "Other";
                pkt.appProtocol = "Unknown";
                pkt.summary = "IP Protocol: " + to_string(ipHeader->ip_p);
            }
        } else {
            pkt.l4Protocol = "Other";
            pkt.srcIP = "N/A";
            pkt.destIP = "N/A";
            pkt.appProtocol = "Unknown";
            pkt.summary = "EtherType: 0x" + to_string(etherType);
        }

        bool parsed = false;
        for (auto parser : parsers) {
            if (parser->canParse(pkt)) {
                parser->parse(pkt);
                parsed = true;
                break;
            }
        }
        if (!parsed && pkt.appProtocol.empty()) {
            pkt.appProtocol = "Unknown";
            pkt.summary = "Unidentified traffic";
        }

        packets.push_back(pkt);
        stats.addPacket(pkt);
        
        if (dbConnected) {
            batchInserter.addPacket(sessionId, header->ts.tv_sec, pkt.srcIP, pkt.destIP,
                                   pkt.srcPort, pkt.destPort, pkt.l4Protocol,
                                   pkt.appProtocol, pkt.length, pkt.summary);
            statsUpdater.addSourceIP(pkt.srcIP);
            statsUpdater.addDestIP(pkt.destIP);
            statsUpdater.addProtocol(pkt.l4Protocol);
        }
    }

    if (dbConnected) {
        cout << "✓ Flushing remaining packets..." << endl;
        batchInserter.flush();
        cout << "✓ Updating database statistics..." << endl;
        statsUpdater.updateDatabase();
    }

    for (const auto& pkt : packets) {
        result["packets"].push_back(pkt.to_json());
    }

    result["success"] = true;
    result["stats"] = stats.getStats(packetCount);

    for (auto parser : parsers) delete parser;
    pcap_close(handle);

    cout << "✓ Analysis complete: " << packetCount << " packets processed" << endl;
    return result;
}

// ===================== CORS HELPER =====================
crow::response add_cors_headers(crow::response&& res) {
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");
    return move(res);
}

// ===================== MAIN SERVER =====================
int main() {
    DBConfig dbConfig;
    dbConfig.host = "localhost";
    dbConfig.user = "root";
    dbConfig.password = "ROOT";
    dbConfig.database = "project";
    dbConfig.port = 3306;

    DatabaseConnection db(dbConfig);
    bool dbConnected = db.connect();
    
    if (!dbConnected) {
        cout << "⚠ Warning: Database connection failed. Server will run without database storage." << endl;
    }

    crow::SimpleApp app;

    if (!filesystem::exists("uploads")) {
        filesystem::create_directory("uploads");
    }
    if (!filesystem::exists("static")) {
        filesystem::create_directory("static");
    }

    CROW_ROUTE(app, "/")([](const crow::request& req) {
        ifstream file("static/index.html");
        if (!file.is_open()) return add_cors_headers(crow::response(404, "File not found"));
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        auto res = crow::response(200, content);
        res.set_header("Content-Type", "text/html");
        return add_cors_headers(move(res));
    });

    CROW_ROUTE(app, "/style.css")([](const crow::request& req) {
        ifstream file("static/style.css");
        if (!file.is_open()) return add_cors_headers(crow::response(404, "File not found"));
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        auto res = crow::response(200, content);
        res.set_header("Content-Type", "text/css");
        return add_cors_headers(move(res));
    });

    CROW_ROUTE(app, "/script.js")([](const crow::request& req) {
        ifstream file("static/script.js");
        if (!file.is_open()) return add_cors_headers(crow::response(404, "File not found"));
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        auto res = crow::response(200, content);
        res.set_header("Content-Type", "application/javascript");
        return add_cors_headers(move(res));
    });

    // NEW: GET /sessions - Retrieve all saved sessions
    CROW_ROUTE(app, "/sessions").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        json response;
        
        try {
            if (!db.isConnected()) {
                response["success"] = false;
                response["error"] = "Database not connected";
                response["sessions"] = json::array();
                auto res = crow::response(503, response.dump());
                res.set_header("Content-Type", "application/json");
                return add_cors_headers(move(res));
            }
            
            json sessions = db.getSessions();
            response["success"] = true;
            response["sessions"] = sessions;
            
            auto res = crow::response(200, response.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));
            
        } catch (const exception& e) {
            response["success"] = false;
            response["error"] = string("Exception: ") + e.what();
            response["sessions"] = json::array();
            auto res = crow::response(500, response.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));
        }
    });

    // NEW: GET /analyze/<session_id> - Retrieve data for a specific session
    CROW_ROUTE(app, "/analyze/<int>").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req, int sessionId) {
        json response;
        
        try {
            if (!db.isConnected()) {
                response["success"] = false;
                response["error"] = "Database not connected";
                response["packets"] = json::array();
                response["ip_stats"] = json::array();
                response["protocol_stats"] = json::array();
                auto res = crow::response(503, response.dump());
                res.set_header("Content-Type", "application/json");
                return add_cors_headers(move(res));
            }
            
            json sessionData = db.getSessionData(sessionId);
            
            if (sessionData.contains("error")) {
                response["success"] = false;
                response["error"] = sessionData["error"];
                response["packets"] = json::array();
                response["ip_stats"] = json::array();
                response["protocol_stats"] = json::array();
                auto res = crow::response(404, response.dump());
                res.set_header("Content-Type", "application/json");
                return add_cors_headers(move(res));
            }
            
            response["success"] = true;
            response["session_id"] = sessionId;
            response["packets"] = sessionData["packets"];
            response["ip_stats"] = sessionData["ip_stats"];
            response["protocol_stats"] = sessionData["protocol_stats"];
            
            auto res = crow::response(200, response.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));
            
        } catch (const exception& e) {
            response["success"] = false;
            response["error"] = string("Exception: ") + e.what();
            response["packets"] = json::array();
            response["ip_stats"] = json::array();
            response["protocol_stats"] = json::array();
            auto res = crow::response(500, response.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));
        }
    });

    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        cout << "\n=== New Upload Request ===" << endl;
        json response;
        
        string filepath = "uploads/upload_" + to_string(time(NULL)) + "_" + 
                         to_string(rand() % 10000) + ".pcap";
        
        try {
            if (req.body.empty()) {
                response["success"] = false;
                response["error"] = "Empty file uploaded";
                response["packets"] = json::array();
                response["stats"] = json::object();
                auto res = crow::response(400, response.dump());
                res.set_header("Content-Type", "application/json");
                return add_cors_headers(move(res));
            }
            
            ofstream outfile(filepath, ios::binary);
            if (!outfile.is_open()) {
                response["success"] = false;
                response["error"] = "Could not create upload file";
                response["packets"] = json::array();
                response["stats"] = json::object();
                auto res = crow::response(500, response.dump());
                res.set_header("Content-Type", "application/json");
                return add_cors_headers(move(res));
            }
            outfile.write(req.body.c_str(), req.body.size());
            outfile.close();

            cout << "✓ File saved: " << filepath << " (" << req.body.size() << " bytes)" << endl;
            
            // Create session in database
            int sessionId = -1;
            if (db.isConnected()) {
                string sessionName = "upload_" + to_string(time(NULL));
                sessionId = db.createSession(sessionName, filepath);
                
                if (sessionId < 0) {
                    cout << "⚠ Warning: Failed to create session, continuing without DB storage" << endl;
                    // If session creation fails, treat as if DB is disconnected for this upload
                    response["success"] = false;
                    response["error"] = "Failed to create database session";
                    response["packets"] = json::array();
                    response["stats"] = json::object();
                    
                    try {
                        if (filesystem::exists(filepath)) {
                            filesystem::remove(filepath);
                        }
                    } catch (...) {}
                    
                    auto res = crow::response(500, response.dump());
                    res.set_header("Content-Type", "application/json");
                    return add_cors_headers(move(res));
                } else {
                    cout << "✓ Using session_id: " << sessionId << " for this upload" << endl;
                }
            }
            
            // Reset cancel flag before starting new analysis
            cancelAnalysis.store(false);
            
            // Run analysis synchronously (blocking)
            json analysis_result = analyze_pcap(filepath, db, sessionId, cancelAnalysis);

            // Clean up uploaded file after analysis
            try {
                if (filesystem::exists(filepath)) {
                    filesystem::remove(filepath);
                    cout << "✓ Cleaned up temporary file: " << filepath << endl;
                }
            } catch (const exception& e) {
                cerr << "⚠ Warning: Could not delete temp file: " << e.what() << endl;
            }

            // Ensure response always has required fields
            if (!analysis_result.contains("packets")) {
                analysis_result["packets"] = json::array();
            }
            if (!analysis_result.contains("stats")) {
                analysis_result["stats"] = json::object();
            }
            
            auto res = crow::response(200, analysis_result.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));

        } catch (const exception& e) {
            response["success"] = false;
            response["error"] = string("Exception: ") + e.what();
            response["packets"] = json::array();
            response["stats"] = json::object();
            
            cout << "ERROR: " << e.what() << endl;
            
            try {
                if (filesystem::exists(filepath)) {
                    filesystem::remove(filepath);
                }
            } catch (...) {}
            
            auto res = crow::response(500, response.dump());
            res.set_header("Content-Type", "application/json");
            return add_cors_headers(move(res));
        }
    });

    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::OPTIONS)
    ([](const crow::request& req) {
        return add_cors_headers(crow::response(200, ""));
    });

    CROW_ROUTE(app, "/clear").methods(crow::HTTPMethod::POST)([](const crow::request&){
        json response;
        cancelAnalysis.store(true);
        
        // Give a moment for any running analysis to notice the cancel flag
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        cancelAnalysis.store(false);
        response["success"] = true;
        response["message"] = "Analysis cancelled and cleared.";
        auto res = crow::response(200, response.dump());
        res.set_header("Content-Type", "application/json");
        return add_cors_headers(move(res));
    });

    std::signal(SIGINT, [](int){ 
        cout << "\n⚠ SIGINT received: shutting down..." << endl;
        cancelAnalysis.store(true);
    });

    cout << "\n╔═══════════════════════════════════════╗" << endl;
    cout << "║   NetScope Analyzer Backend Server    ║" << endl;
    cout << "╚═══════════════════════════════════════╝" << endl;
    cout << "\n✓ Server: http://localhost:8080" << endl;
    cout << "✓ Upload: POST http://localhost:8080/upload" << endl;
    cout << "✓ Sessions: GET http://localhost:8080/sessions" << endl;
    cout << "✓ Analyze: GET http://localhost:8080/analyze/<session_id>" << endl;
    cout << "✓ Database: " << (dbConnected ? "Connected" : "Disconnected") << endl;
    cout << "\n[Press Ctrl+C to stop]" << endl;

    app.port(8080).multithreaded().run();

    return 0;
}
