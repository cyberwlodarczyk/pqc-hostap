#ifndef PQC_H
#define PQC_H

#include "utils/includes.h"
#include "utils/common.h"

#define PQC_GROUP_MLKEM512 35
#define PQC_GROUP_MLKEM768 36
#define PQC_GROUP_MLKEM1024 37

#define PQC_MLKEM_LEN_SHARED_SECRET 32

#define PQC_TEMPO_LEN_ADDRESS ETH_ALEN
#define PQC_TEMPO_LEN_COUNTER 2
#define PQC_TEMPO_LEN_MASTER_KEY 32
#define PQC_TEMPO_LEN_MASTER_KEY_ID 16
#define PQC_TEMPO_MAX_LEN_REQUEST 1664
#define PQC_TEMPO_MAX_LEN_RESPONSE 1568
#define PQC_TEMPO_MAX_LEN_TAG 64

bool pqc_is_group(int id);

typedef struct
{
    int group;
    size_t len_pk;
    size_t len_sk;
    size_t len_ct;
    u8 *sk;
} pqc_mlkem;

pqc_mlkem *pqc_mlkem_init(int group);

int pqc_mlkem_keygen(pqc_mlkem *m, u8 *pk);

int pqc_mlkem_encaps(const pqc_mlkem *m, u8 *ct, u8 *ss, const u8 *pk);

int pqc_mlkem_decaps(const pqc_mlkem *m, u8 *ss, const u8 *ct);

void pqc_mlkem_deinit(pqc_mlkem *m);

typedef struct
{
    int group;
    bool is_initiator;
    size_t len_pk;
    size_t len_sk;
    size_t len_req;
    size_t len_res;
    size_t len_tag;
    u8 *sid;
    u8 *pwd;
    u8 *pk;
    u8 *sk;
    u8 *ss;
} pqc_tempo;

pqc_tempo *pqc_tempo_init(int group);

bool pqc_tempo_check_req(const pqc_tempo *t, const u8 *req);

int pqc_tempo_prepare(
    pqc_tempo *t,
    const u8 *own_addr,
    const u8 *peer_addr,
    const u8 *password,
    size_t password_len);

int pqc_tempo_keygen(pqc_tempo *t, u8 *req);

int pqc_tempo_encaps(pqc_tempo *t, u8 *res, const u8 *req);

int pqc_tempo_decaps(pqc_tempo *t, const u8 *res);

int pqc_tempo_confirm(
    const pqc_tempo *t,
    u8 *tag,
    const u8 *ctr,
    const u8 *req,
    const u8 *res);

int pqc_tempo_verify(
    const pqc_tempo *t,
    const u8 *peer_tag,
    const u8 *peer_ctr,
    const u8 *req,
    const u8 *res);

int pqc_tempo_finish(
    const pqc_tempo *t,
    u8 *mk,
    u8 *mkid,
    const u8 *req,
    const u8 *res);

void pqc_tempo_deinit(pqc_tempo *t);

#endif
