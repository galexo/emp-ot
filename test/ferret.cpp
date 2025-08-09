// ferret.cpp (order-invariant transcript digest, no Hash copying)

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <cstring>

#include "emp-tool/emp-tool.h"
#include "emp-tool/utils/hash.h"
#include "emp-ot/emp-ot.h"
#include "test/test.h"

using namespace std;
using namespace emp;

static const int threads = 2;

/*** Hashing wrapper for IO (counts bytes + hashes transcript). ***/
template <typename InnerIO>
class HashingIO : public IOChannel<HashingIO<InnerIO>> {
public:
    explicit HashingIO(InnerIO* inner) : inner_(inner) {}

    // IOChannel interface
    void send_data_internal(const void* data, int n) {
        inner_->send_data(data, n);
        h_send_.put(data, n);
        bytes_sent_ += n;
    }
    void recv_data_internal(void* data, int n) {
        inner_->recv_data(data, n);
        h_recv_.put(data, n);
        bytes_recv_ += n;
    }
    void flush() { inner_->flush(); }

    size_t bytes_sent() const { return bytes_sent_; }
    size_t bytes_recv() const { return bytes_recv_; }

    // Destructive finalize: outputs digests and consumes internal state.
    void finalize_digests(char out_send[Hash::DIGEST_SIZE],
                          char out_recv[Hash::DIGEST_SIZE]) {
        h_send_.digest(out_send);
        h_recv_.digest(out_recv);
    }

private:
    InnerIO* inner_;
    Hash h_send_, h_recv_;
    size_t bytes_sent_ = 0, bytes_recv_ = 0;
};

static string hex_bytes(const unsigned char* p, size_t n) {
    ostringstream o; o << std::hex << setfill('0');
    for (size_t i = 0; i < n; ++i) o << setw(2) << (unsigned)p[i];
    return o.str();
}

static void test_ferret(int party,
                        HashingIO<NetIO>* hio[threads],  // hashing IOs for FerretCOT
                        NetIO* base[threads],            // raw NetIO for test_rcot
                        int64_t num_log2) {
    // Setup
    auto t0 = clock_start();
    auto ferretcot = new FerretCOT<HashingIO<NetIO>>(party, threads, hio,
                                                     /*malicious=*/true,
                                                     /*use_pprf=*/true, ferret_b13);
    cout << "party=" << party << "\tphase=setup\t" << fixed << setprecision(2)
         << time_from(t0) << " ms\n";

    // RCOT (internal buffer)
    int64_t num = 1LL << num_log2;
    auto t1 = clock_start();
    double otps1 = double(num) /
        test_rcot<FerretCOT<HashingIO<NetIO>>>(ferretcot, base[0], party, num, /*inplace=*/false)
        * 1e6;
    cout << "party=" << party << "\tphase=rcot\t" << time_from(t1) << " ms"
         << "\tOTps=" << setprecision(1) << otps1 << "\n";

    // RCOT inplace (user buffer)
    uint64_t batch = ferretcot->ot_limit;
    auto t2 = clock_start();
    double otps2 = double(batch) /
        test_rcot<FerretCOT<HashingIO<NetIO>>>(ferretcot, base[0], party, batch, /*inplace=*/true)
        * 1e6;
    cout << "party=" << party << "\tphase=rcot_inplace\t" << time_from(t2) << " ms"
         << "\tOTps=" << setprecision(1) << otps2 << "\n";

    // Ensure all traffic flushed
    for (int i = 0; i < threads; ++i) hio[i]->flush();

    // Totals
    size_t sent = 0, recv = 0;
    for (int i = 0; i < threads; ++i) {
        sent += hio[i]->bytes_sent();
        recv += hio[i]->bytes_recv();
    }

    // Finalize per-thread digests ONCE (destructive), collect both directions
    vector<array<unsigned char, Hash::DIGEST_SIZE>> parts_send, parts_recv;
    parts_send.reserve(threads);
    parts_recv.reserve(threads);
    for (int i = 0; i < threads; ++i) {
        array<unsigned char, Hash::DIGEST_SIZE> ds{}, dr{};
        char tmp_s[Hash::DIGEST_SIZE], tmp_r[Hash::DIGEST_SIZE];
        hio[i]->finalize_digests(tmp_s, tmp_r);  // consumes internal state
        memcpy(ds.data(), tmp_s, Hash::DIGEST_SIZE);
        memcpy(dr.data(), tmp_r, Hash::DIGEST_SIZE);
        parts_send.push_back(ds);
        parts_recv.push_back(dr);
    }

    // Order-invariant aggregation: sort then hash concatenation
    auto aggregate = [](vector<array<unsigned char, Hash::DIGEST_SIZE>>& v) {
        sort(v.begin(), v.end());
        Hash agg;
        for (auto &a : v) agg.put(a.data(), Hash::DIGEST_SIZE);
        array<unsigned char, Hash::DIGEST_SIZE> out{};
        agg.digest(reinterpret_cast<char*>(out.data()));
        return out;
    };
    auto dig_s = aggregate(parts_send);
    auto dig_r = aggregate(parts_recv);

    cout << "party=" << party
         << "\tbytes_sent=" << sent
         << "\tbytes_recv=" << recv
         << "\tsend_digest=" << hex_bytes(dig_s.data(), Hash::DIGEST_SIZE)
         << "\trecv_digest=" << hex_bytes(dig_r.data(), Hash::DIGEST_SIZE)
         << "\n";

    delete ferretcot;
}

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);

    // Underlying NetIO channels
    NetIO* base[threads];
    for (int i = 0; i < threads; ++i) {
        base[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        base[i]->set_nodelay();
    }
    // Hashing wrappers used by FerretCOT
    HashingIO<NetIO>* hio[threads];
    for (int i = 0; i < threads; ++i) hio[i] = new HashingIO<NetIO>(base[i]);

    int64_t num_log2 = (argc > 3) ? atoi(argv[3]) : 24;
    if (num_log2 > 30) { cout << "Large test size! (guard)\n"; return 1; }

    // Simple sync barrier on base[0]
    if (party == ALICE) { base[0]->send_data("OK", 2); base[0]->flush(); }
    else { char tmp[2]; base[0]->recv_data(tmp, 2); }

    test_ferret(party, hio, base, num_log2);

    for (int i = 0; i < threads; ++i) { delete hio[i]; delete base[i]; }
    return 0;
}
