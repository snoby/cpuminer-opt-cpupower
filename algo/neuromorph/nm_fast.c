/* Vendored from github.com/CereblixCRB/cereblix (MIT License).
 * Copyright (c) 2026 Cereblix (CRB). See LICENSE-neuromorph for the full text.
 */
/* nm_fast — high-performance NeuroMorph core. Byte-identical to consensus.
 *
 * CAUTION for this fork's build.sh: it defaults to -ffast-math for yespower's
 * benefit, but NeuroMorph's consensus digest depends on exact IEEE-754
 * semantics (see the isnan/isinf/==0 float renormalization in vm_one_loop's
 * Lfix path) -- -ffast-math implies -ffinite-math-only, which lets the
 * compiler assume isnan()/isinf() are always false and optimize the checks
 * away, silently producing a WRONG (non-consensus) hash. Build this file
 * (and neuromorph.c) WITHOUT -ffast-math; the pragma below only protects the
 * GCC path (Clang does not support "no-tree-vectorize"/"no-fast-math" via
 * #pragma GCC optimize).
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize("no-tree-vectorize","no-fast-math")
#endif
#include "nm_fast.h"
#include "nm_params.h"
#include "nm_sha256.h"
#include "nm_aes.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <x86intrin.h>
#include <cpuid.h>

enum { opIADD, opIMUL, opIMULH, opIXOR, opIROTR, opINEG, opFADD, opFMUL,
       opFDIV, opFSQRT, opLOAD, opSTORE, opCBRANCH, opAESR, opXDOM };

static inline uint64_t le64(const uint8_t *b){ uint64_t v; memcpy(&v,b,8); return v; } /* x86: LE */
static inline void put64(uint8_t *b, uint64_t v){ memcpy(b,&v,8); }
static inline uint32_t le32(const uint8_t *b){ uint32_t v; memcpy(&v,b,4); return v; }
static inline double bits2d(uint64_t x){ double d; memcpy(&d,&x,8); return d; }
static inline uint64_t d2bits(double d){ uint64_t x; memcpy(&x,&d,8); return x; }
static inline double normFloat(uint64_t x){ uint64_t b=((uint64_t)1023<<52)|(x&0x000FFFFFFFFFFFFFULL); return bits2d(b); }
static inline uint64_t rotl64(uint64_t x,int k){ unsigned s=((unsigned)k)&63u; if(!s) return x; return (x<<s)|(x>>(64-s)); }
static inline uint64_t mulhi64(uint64_t a,uint64_t b){ return (uint64_t)(((unsigned __int128)a*(unsigned __int128)b)>>64); }

/* scratch-fill dispatch: pick the fastest AES path the CPU can run, runtime.
 * Both paths emit byte-identical scratch (AES is defined per 128-bit lane, so
 * VAES-256's two-blocks-per-instruction result equals two AES-NI blocks). */
typedef void (*nm_fillfn)(const nm_epoch*, nm_lane*, const uint8_t*);
static void fill_scratch(const nm_epoch *e, nm_lane *l, const uint8_t seed[32]);
static void select_fill(void);
static nm_fillfn g_fillfn = fill_scratch;
static const char *g_fillname = "AES-NI";

void nm_fast_epoch_init(nm_epoch *e, const uint8_t seed[32]){
    select_fill();
    nm_derive_params(seed, &e->params);
    nm_aes128_expand(&e->aes, e->params.aes_key);
    e->dataset = NULL;
}
const char *nm_fast_fill_name(void){ select_fill(); return g_fillname; }
void nm_fast_set_dataset(nm_epoch *e, uint64_t *dataset){ e->dataset = dataset; }

int nm_fast_lane_init(nm_lane *l){
    l->scratch=(uint64_t*)malloc((size_t)NM_SCRATCH_WORDS*8);
    l->prog=(nm_instr*)malloc((size_t)NM_PROG_MAX*sizeof(nm_instr));
    l->taken=(uint8_t*)malloc(NM_PROG_MAX);
    return (l->scratch&&l->prog&&l->taken)?0:-1;
}
void nm_fast_lane_free(nm_lane *l){ free(l->scratch); free(l->prog); free(l->taken); memset(l,0,sizeof*l); }
void nm_fast_lane_attach(nm_lane *l, void *scratch){ l->scratch=(uint64_t*)scratch; }

void nm_fast_build_dataset(const nm_epoch *e, uint64_t *dataset){
    nm_aes128 a; nm_aes128_expand(&a, e->params.dataset_key);
    __m128i rk[11]; for(int r=0;r<11;r++) rk[r]=_mm_loadu_si128((const __m128i*)(a.rk+16*r));
    for(uint32_t i=0;i<NM_DATASET_WORDS;i+=16){
        __m128i m[8];
        for(int j=0;j<8;j++) m[j]=_mm_xor_si128(_mm_set_epi64x(0,(long long)(uint64_t)(i+2*j)),rk[0]);
        for(int r=1;r<10;r++){ __m128i k=rk[r]; for(int j=0;j<8;j++) m[j]=_mm_aesenc_si128(m[j],k); }
        for(int j=0;j<8;j++) _mm_storeu_si128((__m128i*)&dataset[i+2*j],_mm_aesenclast_si128(m[j],rk[10]));
    }
}

/* optimized 2 MiB scratchpad fill: inlined 8-way AES-CTR, direct __m128i stores */
static void fill_scratch(const nm_epoch *e, nm_lane *l, const uint8_t seed[32]){
    (void)e;
    uint8_t key[32],t[33]; memcpy(t,seed,32); t[32]=0x53; nm_sha256(t,33,key);
    nm_aes128 a; nm_aes128_expand(&a,key);
    __m128i rk[11]; for(int r=0;r<11;r++) rk[r]=_mm_loadu_si128((const __m128i*)(a.rk+16*r));
    uint64_t khi; memcpy(&khi,key+24,8);
    uint64_t *sc=l->scratch;
    for(uint32_t i=0;i<NM_SCRATCH_WORDS;i+=16){
        __m128i m0=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+0)),rk[0]);
        __m128i m1=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+2)),rk[0]);
        __m128i m2=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+4)),rk[0]);
        __m128i m3=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+6)),rk[0]);
        __m128i m4=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+8)),rk[0]);
        __m128i m5=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+10)),rk[0]);
        __m128i m6=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+12)),rk[0]);
        __m128i m7=_mm_xor_si128(_mm_set_epi64x((long long)khi,(long long)(uint64_t)(i+14)),rk[0]);
        for(int r=1;r<10;r++){ __m128i k=rk[r];
            m0=_mm_aesenc_si128(m0,k); m1=_mm_aesenc_si128(m1,k); m2=_mm_aesenc_si128(m2,k); m3=_mm_aesenc_si128(m3,k);
            m4=_mm_aesenc_si128(m4,k); m5=_mm_aesenc_si128(m5,k); m6=_mm_aesenc_si128(m6,k); m7=_mm_aesenc_si128(m7,k); }
        __m128i kl=rk[10];
        _mm_storeu_si128((__m128i*)&sc[i+0], _mm_aesenclast_si128(m0,kl));
        _mm_storeu_si128((__m128i*)&sc[i+2], _mm_aesenclast_si128(m1,kl));
        _mm_storeu_si128((__m128i*)&sc[i+4], _mm_aesenclast_si128(m2,kl));
        _mm_storeu_si128((__m128i*)&sc[i+6], _mm_aesenclast_si128(m3,kl));
        _mm_storeu_si128((__m128i*)&sc[i+8], _mm_aesenclast_si128(m4,kl));
        _mm_storeu_si128((__m128i*)&sc[i+10],_mm_aesenclast_si128(m5,kl));
        _mm_storeu_si128((__m128i*)&sc[i+12],_mm_aesenclast_si128(m6,kl));
        _mm_storeu_si128((__m128i*)&sc[i+14],_mm_aesenclast_si128(m7,kl));
    }
}

#if defined(__x86_64__) || defined(_M_X64)
/* VAES-256 scratch fill: 2 AES blocks per instruction (Zen3+/Ice Lake+). Same
 * 8-blocks-per-iteration shape as the AES-NI path above, just packed two blocks
 * to a 256-bit register, so the stored bytes are identical. ~2x the AES issue
 * rate on the 49%-of-the-hash fill phase. */
__attribute__((target("avx2,vaes")))
static void fill_scratch_vaes256(const nm_epoch *e, nm_lane *l, const uint8_t seed[32]){
    (void)e;
    uint8_t key[32],t[33]; memcpy(t,seed,32); t[32]=0x53; nm_sha256(t,33,key);
    nm_aes128 a; nm_aes128_expand(&a,key);
    __m256i rk[11];
    for(int r=0;r<11;r++) rk[r]=_mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)(a.rk+16*r)));
    uint64_t khi; memcpy(&khi,key+24,8); long long kh=(long long)khi;
    uint64_t *sc=l->scratch;
    for(uint32_t i=0;i<NM_SCRATCH_WORDS;i+=16){
        __m256i y0=_mm256_xor_si256(_mm256_set_epi64x(kh,(long long)(uint64_t)(i+2 ),kh,(long long)(uint64_t)(i+0 )),rk[0]);
        __m256i y1=_mm256_xor_si256(_mm256_set_epi64x(kh,(long long)(uint64_t)(i+6 ),kh,(long long)(uint64_t)(i+4 )),rk[0]);
        __m256i y2=_mm256_xor_si256(_mm256_set_epi64x(kh,(long long)(uint64_t)(i+10),kh,(long long)(uint64_t)(i+8 )),rk[0]);
        __m256i y3=_mm256_xor_si256(_mm256_set_epi64x(kh,(long long)(uint64_t)(i+14),kh,(long long)(uint64_t)(i+12)),rk[0]);
        for(int r=1;r<10;r++){ __m256i k=rk[r];
            y0=_mm256_aesenc_epi128(y0,k); y1=_mm256_aesenc_epi128(y1,k);
            y2=_mm256_aesenc_epi128(y2,k); y3=_mm256_aesenc_epi128(y3,k); }
        __m256i kl=rk[10];
        _mm256_storeu_si256((__m256i*)&sc[i+0], _mm256_aesenclast_epi128(y0,kl));
        _mm256_storeu_si256((__m256i*)&sc[i+4], _mm256_aesenclast_epi128(y1,kl));
        _mm256_storeu_si256((__m256i*)&sc[i+8], _mm256_aesenclast_epi128(y2,kl));
        _mm256_storeu_si256((__m256i*)&sc[i+12],_mm256_aesenclast_epi128(y3,kl));
    }
}

/* VAES-512 scratch fill: 4 AES blocks per instruction on AVX-512+VAES (Zen4/Zen5
 * Genoa/Turin/Ryzen 7000+, Intel Ice Lake-SP / Sapphire Rapids / Tiger Lake+).
 * 16 blocks per iteration in 4 ZMM regs; per-128-bit-lane AES -> identical bytes.
 * clang splits 512-bit AVX-512 behind the 'evex512' feature; GCC doesn't use that
 * name, so select the right target string per compiler. */
#if defined(__clang__)
__attribute__((target("avx512f,vaes,evex512")))
#else
__attribute__((target("avx512f,vaes")))
#endif
static void fill_scratch_vaes512(const nm_epoch *e, nm_lane *l, const uint8_t seed[32]){
    (void)e;
    uint8_t key[32],t[33]; memcpy(t,seed,32); t[32]=0x53; nm_sha256(t,33,key);
    nm_aes128 a; nm_aes128_expand(&a,key);
    __m512i rk[11];
    for(int r=0;r<11;r++) rk[r]=_mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)(a.rk+16*r)));
    uint64_t khi; memcpy(&khi,key+24,8); long long kh=(long long)khi;
    uint64_t *sc=l->scratch;
    for(uint32_t i=0;i<NM_SCRATCH_WORDS;i+=32){
        __m512i z0=_mm512_xor_si512(_mm512_set_epi64(kh,(long long)(uint64_t)(i+6 ),kh,(long long)(uint64_t)(i+4 ),kh,(long long)(uint64_t)(i+2 ),kh,(long long)(uint64_t)(i+0 )),rk[0]);
        __m512i z1=_mm512_xor_si512(_mm512_set_epi64(kh,(long long)(uint64_t)(i+14),kh,(long long)(uint64_t)(i+12),kh,(long long)(uint64_t)(i+10),kh,(long long)(uint64_t)(i+8 )),rk[0]);
        __m512i z2=_mm512_xor_si512(_mm512_set_epi64(kh,(long long)(uint64_t)(i+22),kh,(long long)(uint64_t)(i+20),kh,(long long)(uint64_t)(i+18),kh,(long long)(uint64_t)(i+16)),rk[0]);
        __m512i z3=_mm512_xor_si512(_mm512_set_epi64(kh,(long long)(uint64_t)(i+30),kh,(long long)(uint64_t)(i+28),kh,(long long)(uint64_t)(i+26),kh,(long long)(uint64_t)(i+24)),rk[0]);
        for(int r=1;r<10;r++){ __m512i k=rk[r];
            z0=_mm512_aesenc_epi128(z0,k); z1=_mm512_aesenc_epi128(z1,k);
            z2=_mm512_aesenc_epi128(z2,k); z3=_mm512_aesenc_epi128(z3,k); }
        __m512i kl=rk[10];
        _mm512_storeu_si512((void*)&sc[i+0],  _mm512_aesenclast_epi128(z0,kl));
        _mm512_storeu_si512((void*)&sc[i+8],  _mm512_aesenclast_epi128(z1,kl));
        _mm512_storeu_si512((void*)&sc[i+16], _mm512_aesenclast_epi128(z2,kl));
        _mm512_storeu_si512((void*)&sc[i+24], _mm512_aesenclast_epi128(z3,kl));
    }
}
#endif

/* Pick the fastest scratch-fill the CPU can run, AUTO-BENCHMARKED at startup and
 * BYTE-VERIFIED against AES-NI - so every generation runs at its max with zero
 * config and a wrong/slow path can never be chosen:
 *   AES-NI    : any AES+SSE2 x86 (Zen2/Rome, Haswell, ...)
 *   VAES-256  : VAES (Zen3+, Ice Lake+)
 *   VAES-512  : VAES + AVX-512 (Zen4/Zen5, Ice Lake-SP / Sapphire Rapids, ...)
 * CPUID gates which paths are even attempted; each candidate must reproduce the
 * AES-NI bytes exactly, then is timed (min of repeated rdtsc runs); fastest wins.
 * Override/A-B: NM_FILL=aesni|vaes256|vaes512, NM_NO_VAES=1 (force AES-NI). */
static void select_fill(void){
    static int done=0; if(done) return; done=1;

    unsigned a,b,c,d; int has_vaes=0, has_avx512=0;
    if(__get_cpuid_count(7,0,&a,&b,&c,&d)){ has_vaes=(c>>9)&1u; has_avx512=(b>>16)&1u; } /* ECX[9]=VAES, EBX[16]=AVX512F */

    nm_fillfn fn[3]={ fill_scratch, 0, 0 };
    const char *nm[3]={ "AES-NI","VAES-256","VAES-512" };
#if defined(__x86_64__) || defined(_M_X64)
    if(has_vaes)               fn[1]=fill_scratch_vaes256;
    if(has_vaes && has_avx512) fn[2]=fill_scratch_vaes512;
#endif

    int force=-1;
    if(getenv("NM_NO_VAES")) force=0;
    { const char *e=getenv("NM_FILL");
      if(e){ if(!strcmp(e,"aesni"))force=0; else if(!strcmp(e,"vaes256"))force=1; else if(!strcmp(e,"vaes512"))force=2; } }
    if(force>=0 && force<3 && fn[force]){ g_fillfn=fn[force]; g_fillname=nm[force]; return; }

    uint64_t *sc =(uint64_t*)malloc((size_t)NM_SCRATCH_WORDS*8);
    uint64_t *ref=(uint64_t*)malloc((size_t)NM_SCRATCH_WORDS*8);
    if(!sc||!ref){ free(sc); free(ref); g_fillfn=fill_scratch; g_fillname="AES-NI"; return; }
    nm_lane lane; lane.scratch=sc; lane.prog=0; lane.taken=0;
    nm_epoch dummy; memset(&dummy,0,sizeof dummy);
    uint8_t seed[32]; for(int i=0;i<32;i++) seed[i]=(uint8_t)(i*11u+3u);
    fill_scratch(&dummy,&lane,seed); memcpy(ref,sc,(size_t)NM_SCRATCH_WORDS*8);

    int best=0; unsigned long long bestcyc=~0ull;
    for(int k=0;k<3;k++){
        if(!fn[k]) continue;
        fn[k](&dummy,&lane,seed);
        if(memcmp(sc,ref,(size_t)NM_SCRATCH_WORDS*8)!=0) continue;        /* reject wrong bytes */
        unsigned long long bc=~0ull;
        for(int rep=0;rep<4;rep++){
            unsigned long long t0=__rdtsc();
            fn[k](&dummy,&lane,seed); fn[k](&dummy,&lane,seed);
            unsigned long long t1=__rdtsc();
            if(t1-t0<bc) bc=t1-t0;
        }
        if(bc<bestcyc){ bestcyc=bc; best=k; }
    }
    free(sc); free(ref);
    g_fillfn=fn[best]?fn[best]:fill_scratch; g_fillname=nm[best];
}

static void gen_program(const nm_epoch *e, nm_lane *l, const uint8_t seed[32]){
    uint8_t key[32],t[33]; memcpy(t,seed,32); t[32]=0x50; nm_sha256(t,33,key);
    nm_aes128 a; nm_aes128_expand(&a,key);
    int progSize=e->params.prog_size;
    uint8_t stream[NM_PROG_MAX*8],in[16],o[16];
    memcpy(in,key+16,16); int slen=0,need=progSize*8;
    while(slen<need){ nm_aes128_encrypt(&a,in,o); memcpy(stream+slen,o,16); slen+=16; memcpy(in,o,16); put64(in,le64(in)+1); }
    const uint8_t *ot=e->params.op_table; nm_instr *pr=l->prog;
    for(int i=0;i<progSize;i++){ const uint8_t*b=stream+i*8;
        pr[i].op=ot[b[0]]; pr[i].dst=b[1]; pr[i].src=b[2]; pr[i].imm=le32(b+4); }
}

/* run ONE outer loop of the VM (the pc instruction stream) for one lane.
 * Updates r[16] and f[8] and the lane scratchpad. Computed-goto dispatch. */
static void vm_one_loop(const nm_epoch *e, nm_lane *l, uint64_t r[16], double f[8], int loop){
    const int progSize=e->params.prog_size;
    const uint64_t branchMask=e->params.branch_mask, rotSalt=e->params.rot_salt;
    uint64_t *sc=l->scratch; nm_instr *prog=l->prog; uint8_t *taken=l->taken;
    uint8_t aesIn[16],aesOut[16];
    static const void *const dtab[15]={ &&L_IADD,&&L_IMUL,&&L_IMULH,&&L_IXOR,&&L_IROTR,&&L_INEG,
        &&L_FADD,&&L_FMUL,&&L_FDIV,&&L_FSQRT,&&L_LOAD,&&L_STORE,&&L_CBRANCH,&&L_AESR,&&L_XDOM };
    memset(taken,0,progSize);
    int pc=0; nm_instr *ins; int d,s; uint32_t imm;
    #define DISP() do{ ins=&prog[pc]; d=ins->dst&15; s=ins->src&15; imm=ins->imm; goto *dtab[ins->op]; }while(0)
    #define ADV()  do{ if(++pc>=progSize) goto Lend; DISP(); }while(0)
    if(pc<progSize){ DISP(); } else goto Lend;
    L_IADD:  r[d]+=r[s]+(uint64_t)imm; ADV();
    L_IMUL:  r[d]*=r[s]|1ULL; ADV();
    L_IMULH: r[d]=mulhi64(r[d],r[s])^(uint64_t)imm; ADV();
    L_IXOR:  r[d]^=r[s]+rotSalt; ADV();
    L_IROTR: r[d]=rotl64(r[d],-(int)((r[s]^(uint64_t)imm)&63)); ADV();
    L_INEG:  r[d]=~r[d]+(uint64_t)imm; ADV();
    L_FADD:  f[d&7]=f[d&7]+f[s&7]; goto Lfix;
    L_FMUL:  f[d&7]=f[d&7]*f[s&7]; goto Lfix;
    L_FDIV:  f[d&7]=f[d&7]/normFloat(d2bits(f[s&7])); goto Lfix;
    L_FSQRT: f[d&7]=sqrt(fabs(f[d&7]));
    Lfix:    { double v=f[d&7]; if(isnan(v)||isinf(v)||v==0.0) f[d&7]=normFloat(r[d]|1ULL); } ADV();
    L_LOAD:  { uint64_t a=(r[s]+(uint64_t)imm)&NM_SCRATCH_MASK; r[d]^=sc[a>>3]; } ADV();
    L_STORE: { uint64_t a=(r[d]+(uint64_t)imm)&NM_SCRATCH_MASK; sc[a>>3]^=r[s]+(uint64_t)loop; } ADV();
    L_CBRANCH:
        if(((r[d]+(uint64_t)imm)&branchMask)==0 && taken[pc]<8){ taken[pc]++; int back=(int)(imm%31)+1; pc-=back; if(pc<0)pc=0; DISP(); }
        ADV();
    L_AESR:  { uint64_t a=(r[s]+(uint64_t)imm)&NM_SCRATCH_MASK&~(uint64_t)15; uint64_t w=a>>3;
        put64(aesIn,sc[w]); put64(aesIn+8,sc[w+1]); nm_aes128_encrypt(&e->aes,aesIn,aesOut);
        sc[w]=le64(aesOut); sc[w+1]=le64(aesOut+8); r[d]^=sc[w]; } ADV();
    L_XDOM:  if((imm&1)==0) r[d]^=d2bits(f[s&7]); else f[d&7]=f[d&7]*normFloat(r[s]); ADV();
    Lend:;
    #undef DISP
    #undef ADV
}

/* per-loop fold of registers back into the scratchpad */
static inline void loop_fold(nm_lane *l, uint64_t r[16], double f[8], int loop){
    uint64_t *sc=l->scratch;
    uint64_t base=(((r[0]^(uint64_t)loop*0x9E3779B97F4A7C15ULL)&NM_SCRATCH_MASK)>>3);
    for(int i=0;i<16;i++) sc[(base+(uint64_t)i)%NM_SCRATCH_WORDS]^=r[i];
    for(int i=0;i<8;i++)  r[i+8]^=d2bits(f[i]);
}

/* AVX2 XOR-fold of the whole 2 MiB scratchpad */
static inline void final_fold(nm_lane *l, uint64_t fold[8]){
    __m256i a0=_mm256_setzero_si256(), a1=_mm256_setzero_si256();
    const __m256i *sp=(const __m256i*)l->scratch;
    for(uint32_t i=0;i<NM_SCRATCH_WORDS/4;i+=2){ a0=_mm256_xor_si256(a0,_mm256_loadu_si256(sp+i)); a1=_mm256_xor_si256(a1,_mm256_loadu_si256(sp+i+1)); }
    _mm256_storeu_si256((__m256i*)fold,a0); _mm256_storeu_si256((__m256i*)(fold+4),a1);
}

static void digest(const uint8_t seed[32], const uint64_t r[16], const double f[8],
                   const uint64_t fold[8], uint8_t out[32]){
    uint8_t buf[4+32+16*8+8*8+8*8]; int n=0;
    memcpy(buf+n,"NMv1",4); n+=4; memcpy(buf+n,seed,32); n+=32;
    for(int i=0;i<16;i++){ put64(buf+n,r[i]); n+=8; }
    for(int i=0;i<8;i++){ put64(buf+n,d2bits(f[i])); n+=8; }
    for(int i=0;i<8;i++){ put64(buf+n,fold[i]); n+=8; }
    nm_sha256(buf,n,out);
}

static inline void seed_of(const uint8_t *header, uint8_t seed[32]){
    uint8_t tmp[8+NM_HEADER_LEN]; memcpy(tmp,"nm-seed|",8); memcpy(tmp+8,header,NM_HEADER_LEN);
    nm_sha256(tmp,8+NM_HEADER_LEN,seed);
}

void nm_fast_hash(const nm_epoch *e, nm_lane *l, const uint8_t *header, uint64_t height, uint8_t out[32]){
    const nm_params *p=&e->params;
    uint8_t seed[32]; seed_of(header,seed);
    int useDS = height>=NM_DATASET_HEIGHT;
    g_fillfn(e,l,seed);
    gen_program(e,l,seed);
    uint64_t r[16]; double f[8];
    for(int i=0;i<4;i++)  r[i]=le64(seed+i*8);
    for(int i=4;i<16;i++) r[i]=l->scratch[i]^p->rot_salt;
    for(int i=0;i<8;i++)  f[i]=normFloat(l->scratch[16+i]);
    const uint64_t rotSalt=p->rot_salt;
    for(int loop=0;loop<p->loops;loop++){
        vm_one_loop(e,l,r,f,loop);
        if(useDS){ uint64_t addr=(r[1]^rotSalt)&NM_DATASET_MASK;
            for(int k=0;k<NM_DATASET_READS_PER_LOOP;k++){ uint64_t v=e->dataset[addr>>3]; r[k&15]^=v; addr=(v+r[(k+1)&15]+(uint64_t)loop)&NM_DATASET_MASK; } }
        loop_fold(l,r,f,loop);
    }
    uint64_t fold[8]; final_fold(l,fold);
    digest(seed,r,f,fold,out);
}

void nm_fast_hash_batch(const nm_epoch *e, nm_lane *lanes, int K,
                        const uint8_t *headers, uint64_t height, uint8_t *out){
    const nm_params *p=&e->params;
    const int loops=p->loops; const uint64_t rotSalt=p->rot_salt;
    const int useDS = height>=NM_DATASET_HEIGHT;
    const uint64_t *ds=e->dataset;

    uint8_t  seed[NM_FAST_MAXLANES][32];
    uint64_t r[NM_FAST_MAXLANES][16];
    double   f[NM_FAST_MAXLANES][8];

    for(int L=0;L<K;L++){
        const uint8_t *hdr=headers + (size_t)L*NM_HEADER_LEN;
        seed_of(hdr, seed[L]);
        g_fillfn(e,&lanes[L],seed[L]);
        gen_program(e,&lanes[L],seed[L]);
        for(int i=0;i<4;i++)  r[L][i]=le64(seed[L]+i*8);
        for(int i=4;i<16;i++) r[L][i]=lanes[L].scratch[i]^p->rot_salt;
        for(int i=0;i<8;i++)  f[L][i]=normFloat(lanes[L].scratch[16+i]);
    }

    for(int loop=0;loop<loops;loop++){
        for(int L=0;L<K;L++) vm_one_loop(e,&lanes[L],r[L],f[L],loop);

        if(useDS){
            uint64_t addr[NM_FAST_MAXLANES];
            for(int L=0;L<K;L++) addr[L]=(r[L][1]^rotSalt)&NM_DATASET_MASK;
            /* interleave the K dependent dataset chains -> K DRAM reads in flight */
            for(int k=0;k<NM_DATASET_READS_PER_LOOP;k++){
                int k0=k&15, k1=(k+1)&15;
                for(int L=0;L<K;L++){
                    uint64_t v=ds[addr[L]>>3];
                    r[L][k0]^=v;
                    addr[L]=(v + r[L][k1] + (uint64_t)loop)&NM_DATASET_MASK;
                }
            }
        }
        for(int L=0;L<K;L++) loop_fold(&lanes[L],r[L],f[L],loop);
    }

    for(int L=0;L<K;L++){
        uint64_t fold[8]; final_fold(&lanes[L],fold);
        digest(seed[L],r[L],f[L],fold, out + (size_t)L*32);
    }
}
