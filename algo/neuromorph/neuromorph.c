/* NeuroMorph (Cereblix CRB) algo-gate glue for cpuminer-opt-cpupower.
 *
 * The hashing core itself (nm_fast.*, nm_params.*, nm_aes.h, nm_sha256.h,
 * nm_neuromorph.h) is vendored near-verbatim from github.com/CereblixCRB/cereblix
 * (MIT license, see LICENSE-neuromorph). This file is the only new code: it
 * wires that core into this codebase's algo_gate/scanhash conventions and
 * owns the shared per-epoch dataset lifecycle.
 */
#include "miner.h"
#include "algo-gate-api.h"
#include "nm_fast.h"
#include "nm_neuromorph.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static inline uint64_t nm_le64dec( const void *pp )
{
   const uint8_t *p = (const uint8_t*) pp;
   return  (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2]<<16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4]<<32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6]<<48) | ((uint64_t)p[7] << 56);
}

/* --- shared, per-epoch state: one dataset/params for ALL mining threads --- */
static pthread_mutex_t nm_epoch_lock = PTHREAD_MUTEX_INITIALIZER;
static nm_epoch  g_nm_epoch;
static uint8_t   g_nm_seed[32];
static int       g_nm_have_seed = 0;
static uint64_t *g_nm_dataset   = NULL;

/* --- per-thread lane (2 MiB scratch + program), malloc'd to opt_n_threads --- */
static nm_lane  *g_nm_lanes  = NULL;
static int       g_nm_nlanes = 0;

/* dedicated lane for hash_suw: called from the workio thread (not a mining
 * thread) once per found share, so it must not touch a live mining lane. */
static pthread_mutex_t nm_suw_lock = PTHREAD_MUTEX_INITIALIZER;
static nm_lane   g_nm_suw_lane;
static int       g_nm_suw_ready = 0;

/* Rebuild the shared epoch/dataset if the job's seed_hash has changed.
 * Called at the top of scanhash_neuromorph/nm_hash_suw; cheap no-op in the
 * (overwhelmingly common) case the epoch hasn't changed since the last call. */
static void nm_ensure_epoch( const uint8_t *header )
{
   uint8_t seed[32];
   nm_get_job_seed_hash( seed );

   pthread_mutex_lock( &nm_epoch_lock );
   if ( !g_nm_have_seed || memcmp( g_nm_seed, seed, 32 ) != 0 )
   {
      memcpy( g_nm_seed, seed, 32 );
      g_nm_have_seed = 1;
      nm_fast_epoch_init( &g_nm_epoch, seed );

      uint64_t height = nm_le64dec( header + 4 );
      if ( height >= NM_DATASET_HEIGHT )
      {
         if ( !g_nm_dataset )
            g_nm_dataset = (uint64_t*) malloc( NM_DATASET_BYTES );
         if ( g_nm_dataset )
         {
            applog( LOG_INFO,
               "NeuroMorph: epoch seed changed, rebuilding %d MiB dataset...",
               NM_DATASET_BYTES >> 20 );
            nm_fast_build_dataset( &g_nm_epoch, g_nm_dataset );
            nm_fast_set_dataset( &g_nm_epoch, g_nm_dataset );
         }
      }
   }
   pthread_mutex_unlock( &nm_epoch_lock );
}

bool nm_miner_thread_init( int thr_id )
{
   if ( !g_nm_lanes )
   {
      pthread_mutex_lock( &nm_epoch_lock );
      if ( !g_nm_lanes )
      {
         g_nm_lanes  = (nm_lane*) calloc( opt_n_threads, sizeof(nm_lane) );
         g_nm_nlanes = opt_n_threads;
      }
      pthread_mutex_unlock( &nm_epoch_lock );
   }
   if ( !g_nm_lanes || thr_id >= g_nm_nlanes )
      return false;
   return nm_fast_lane_init( &g_nm_lanes[thr_id] ) == 0;
}

int scanhash_neuromorph( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
   uint8_t  *header   = (uint8_t*) work->data;      /* raw NM_HEADER_LEN header, no byte-swap */
   uint32_t *nonceptr = (uint32_t*)( header + NM_NONCE_OFFSET ); /* low 32 bits only */
   const uint32_t first_nonce = *nonceptr;
   uint32_t  n         = first_nonce;
   uint64_t  height    = nm_le64dec( header + 4 );

   nm_ensure_epoch( header );

   nm_lane *lane = &g_nm_lanes[ thr_id ];

   uint8_t  raw[32];
   uint32_t vhash[8];

   do {
      *nonceptr = n;
      nm_fast_hash( &g_nm_epoch, lane, header, height, raw );

      /* raw 32-byte big-endian digest -> fulltest()'s word order:
       * word[7-i] = be32dec(raw + 4*i) for i = 0..7 */
      for ( int i = 0; i < 8; i++ )
         vhash[7-i] = be32dec( raw + 4*i );

      if ( fulltest( vhash, work->target ) )
      {
         work_set_target_ratio( work, vhash );
         *hashes_done = n - first_nonce + 1;
         return 1;
      }
      n++;
   } while ( n < max_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

/* Called once per found share from the workio thread (jr2_submit_getwork_result /
 * jr2_build_stratum_request), NOT a mining thread -- must not touch g_nm_lanes[thr_id]. */
void nm_hash_suw( void *output, const void *pdata )
{
   const uint8_t *header = (const uint8_t*) pdata;
   uint64_t height = nm_le64dec( header + 4 );

   nm_ensure_epoch( header );

   pthread_mutex_lock( &nm_suw_lock );
   if ( !g_nm_suw_ready )
      g_nm_suw_ready = ( nm_fast_lane_init( &g_nm_suw_lane ) == 0 );
   if ( g_nm_suw_ready )
      nm_fast_hash( &g_nm_epoch, &g_nm_suw_lane, header, height, (uint8_t*) output );
   else
      memset( output, 0, 32 );
   pthread_mutex_unlock( &nm_suw_lock );
}

/* Model on jr2_get_new_work (cpu-miner.c): compare only the pre-nonce bytes
 * [0, NM_NONCE_OFFSET) -- unlike cryptonight there is no post-nonce region to
 * compare (the nonce is the last field in the 124-byte header), so no second
 * memcmp is needed. Bytes [NM_NONCE_OFFSET+4, NM_NONCE_OFFSET+8) (connection id
 * + pool-assigned extranonce) come along verbatim via work_copy() and are never
 * touched here, since only the low 32-bit word at NM_NONCE_OFFSET is written. */
void nm_get_new_work( struct work* work, struct work* g_work, int thr_id,
                      uint32_t *end_nonce_ptr )
{
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );

   if ( memcmp( work->data, g_work->data, NM_NONCE_OFFSET )
        || ( *nonceptr >= *end_nonce_ptr )
        || ( work->job_id != g_work->job_id ) )
   {
      work_free( work );
      work_copy( work, g_work );
      *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
      *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20;
   }
   else
      ++(*nonceptr);
}

int64_t nm_get_max64( void )
{
   return 0xfffLL;
}

bool register_neuromorph_algo( algo_gate_t* gate )
{
   register_json_rpc2( gate );
   gate->scanhash          = (void*)&scanhash_neuromorph;
   gate->hash_suw          = (void*)&nm_hash_suw;
   gate->get_new_work      = (void*)&nm_get_new_work;
   gate->miner_thread_init = (void*)&nm_miner_thread_init;
   gate->get_max64         = (void*)&nm_get_max64;
   gate->nonce_index       = NM_NONCE_OFFSET;   /* byte offset, see jr2_get_nonceptr */
   gate->work_data_size    = NM_HEADER_LEN;
   gate->optimizations     = AES_OPT | AVX2_OPT;
   return true;
}
