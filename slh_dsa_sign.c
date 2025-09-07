// slh_dsa_sign.c

#include "sha256.h"
#include "slh_dsa_sign.h"
#include "fors_sign.h"

#include <stdint.h>
#include <string.h>

// 你專案裡的參數
// SPX_N, SPX_SK_BYTES, SPX_PK_BYTES, SPX_BYTES, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_MSG_BYTES

// 我先給：PRF_msg 與 H_msg（可直接用）
static void prf_msg(uint8_t R[SPX_N],
                    const uint8_t sk_prf[SPX_N],
                    const uint8_t optrand[SPX_N],
                    const uint8_t *m, size_t mlen)
{
    // R = SHA256(tag=0x01 || SK_PRF || optrand || M) 取前 N bytes
    uint8_t h[32];
    uint8_t tag = 0x01;
    // 拼一個小 buffer（不alloc）
    // 先 hash(SK_PRF || optrand || M)，再把 tag 摻進去一次，避免碰撞
    sha256(sk_prf, SPX_N, h);
    uint8_t buf1[SPX_N + SPX_N + 32];
    memcpy(buf1, optrand, SPX_N);
    memcpy(buf1+SPX_N, h, 32);
    sha256(buf1, SPX_N+32, h);
    // 再把 M 混入
    uint8_t buf2[1 + 32 + 0]; (void)buf2;
    // 直接一次 hash(tag || prev || M)
    // 為了省 RAM，分兩段做：先 tag||prev，再跟 M 串起來 hash
    uint8_t tprev[1+32]; tprev[0]=tag; memcpy(tprev+1, h, 32);
    uint8_t hh[32];
    sha256(m, mlen, hh);
    uint8_t final_in[1+32+32];
    memcpy(final_in, tprev, 1+32);
    memcpy(final_in+1+32, hh, 32);
    sha256(final_in, sizeof(final_in), h);
    memcpy(R, h, SPX_N);
}

static void h_msg(uint8_t mhash[SPX_FORS_MSG_BYTES],
                  uint64_t *tree_idx,
                  uint32_t *leaf_idx,
                  const uint8_t R[SPX_N],
                  const uint8_t pk[SPX_PK_BYTES],
                  const uint8_t *m, size_t mlen)
{
    // H_msg = SHA256(tag=0x02 || R || PK || H(M)) -> 擷取:
    //  - mhash  = 前 SPX_FORS_MSG_BYTES
    //  - tree   = 接下來 8 bytes（小端解）
    //  - leaf   = 再接下來 4 bytes（小端解），按參數集遮罩到合法範圍
    uint8_t tag = 0x02, hM[32], h[32];
    sha256(m, mlen, hM);

    // 拼 (tag || R || PK || hM)
    uint8_t in[1 + SPX_N + SPX_PK_BYTES + 32];
    size_t off = 0;
    in[off++] = tag;
    memcpy(in+off, R, SPX_N); off += SPX_N;
    memcpy(in+off, pk, SPX_PK_BYTES); off += SPX_PK_BYTES;
    memcpy(in+off, hM, 32); off += 32;

    sha256(in, off, h);

    // 擴充輸出（需要超過 32 bytes 時）就再 hash 一次：h2 = SHA256(0x03||h)
    uint8_t h2[32], tag2=0x03, in2[1+32];
    in2[0]=tag2; memcpy(in2+1, h, 32); sha256(in2, sizeof(in2), h2);

    // 填 mhash：先用 h，再不夠用 h2
    size_t need = SPX_FORS_MSG_BYTES;
    size_t cpy1 = need > 32 ? 32 : need;
    memcpy(mhash, h, cpy1);
    if(need > 32) memcpy(mhash+32, h2, need-32);

    // 取 tree_idx（8 bytes）與 leaf_idx（4 bytes）
    // 用 h2 來取索引
    uint8_t idxbuf[12];
    memcpy(idxbuf, h2, 12);
    uint64_t tree = 0;
    for(int i=0;i<8;i++) tree |= ((uint64_t)idxbuf[i]) << (8*i);
    uint32_t leaf = 0;
    for(int i=0;i<4;i++) leaf |= ((uint32_t)idxbuf[8+i]) << (8*i);

    // 遮罩 leaf 到本層葉子範圍 (H/D)
    const unsigned H = SPX_FULL_HEIGHT;
    const unsigned D = SPX_D;
    const unsigned h_per = H / D;
    leaf &= ((1u << h_per) - 1u);

    *tree_idx = tree;
    *leaf_idx = leaf;
}

size_t wots_sign_and_auth(uint8_t *sig_ptr,
                          uint8_t next_root[SPX_N],
                          const uint8_t msgpk[SPX_N],
                          const uint8_t sk_seed[SPX_N],
                          const uint8_t pub_seed[SPX_N],
                          uint64_t tree_idx,
                          uint32_t leaf_idx,
                          unsigned subtree_height);

// fake WOTS+：對 node 做 sha256 當作 next_root；簽章/auth 一律長度 0
size_t wots_sign_and_auth(uint8_t *sig_ptr, uint8_t next_root[SPX_N],
                          const uint8_t msgpk[SPX_N],
                          const uint8_t *sk_seed, const uint8_t *pub_seed,
                          uint64_t tree_idx, uint32_t leaf_idx, unsigned subtree_height)
{
    uint8_t h[32];
    sha256(msgpk, SPX_N, h);
    memcpy(next_root, h, SPX_N);
    (void)sig_ptr; (void)sk_seed; (void)pub_seed; (void)tree_idx; (void)leaf_idx; (void)subtree_height;
    return 0;
}

/* 主簽章：把 R、FORS、各層 WOTS+ 與 auth path 串起來 */
int slh_dsa_sign(uint8_t sig_out[SPX_BYTES],
                 const uint8_t sk[SPX_SK_BYTES],
                 const uint8_t pk[SPX_PK_BYTES],
                 const uint8_t *m, size_t mlen,
                 const uint8_t optrand[SPX_N])
{
    const uint8_t *SK_SEED  = sk + 0*SPX_N;
    const uint8_t *SK_PRF   = sk + 1*SPX_N;
    const uint8_t *PUB_SEED = sk + 2*SPX_N;

    uint8_t *p = sig_out;

    // 1) R
    uint8_t R[SPX_N];
    prf_msg(R, SK_PRF, optrand, m, mlen);
    memcpy(p, R, SPX_N); p += SPX_N;

    // 2) H_msg
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint64_t tree_idx; uint32_t leaf_idx;
    h_msg(mhash, &tree_idx, &leaf_idx, R, pk, m, mlen);

    // 3) FORS.sign -> fors_root
    uint8_t node[SPX_N];
    size_t used = fors_sign(p, node, mhash, SK_SEED, PUB_SEED, tree_idx, leaf_idx);
    p += used;

    // 4) D 層循環：每層 WOTS+.sign(node) + auth_path，計算到上一層 root
    const unsigned H  = SPX_FULL_HEIGHT;
    const unsigned D  = SPX_D;
    const unsigned h  = H / D;

    for(unsigned layer=0; layer<D; ++layer){
        uint32_t leaf = (uint32_t)(leaf_idx & ((1u<<h)-1u));
        uint64_t tree = tree_idx;

        used = wots_sign_and_auth(p, node, node, SK_SEED, PUB_SEED, tree, leaf, h);
        p += used;

        leaf_idx >>= h;
        tree_idx >>= h;
    }

    // 你可以在這裡（debug）檢查 p-sig_out 是否等於 SPX_BYTES
    return 0;
}