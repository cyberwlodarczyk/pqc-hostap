#include "pqc.h"
#include "crypto/crypto.h"
#include "mlkem/mlkem.h"

bool pqc_is_group(int group)
{
    return group == PQC_GROUP_MLKEM512 ||
           group == PQC_GROUP_MLKEM768 ||
           group == PQC_GROUP_MLKEM1024;
}

pqc_mlkem *pqc_mlkem_init(int group)
{
    pqc_mlkem *m = os_zalloc(sizeof(pqc_mlkem));
    if (m == NULL)
    {
        return NULL;
    }
    if (group == PQC_GROUP_MLKEM512)
    {
        m->len_pk = MLKEM512_LEN_PUBLIC_KEY;
        m->len_sk = MLKEM512_LEN_SECRET_KEY;
        m->len_ct = MLKEM512_LEN_CIPHERTEXT;
    }
    else if (group == PQC_GROUP_MLKEM768)
    {
        m->len_pk = MLKEM768_LEN_PUBLIC_KEY;
        m->len_sk = MLKEM768_LEN_SECRET_KEY;
        m->len_ct = MLKEM768_LEN_CIPHERTEXT;
    }
    else if (group == PQC_GROUP_MLKEM1024)
    {
        m->len_pk = MLKEM1024_LEN_PUBLIC_KEY;
        m->len_sk = MLKEM1024_LEN_SECRET_KEY;
        m->len_ct = MLKEM1024_LEN_CIPHERTEXT;
    }
    else
    {
        os_free(m);
        return NULL;
    }
    m->group = group;
    return m;
}

int pqc_mlkem_keygen(pqc_mlkem *m, u8 *pk)
{
    u8 *sk = os_zalloc(m->len_sk);
    if (sk == NULL)
    {
        return -1;
    }
    int ret;
    if (m->group == PQC_GROUP_MLKEM512)
    {
        ret = mlkem512_keypair(pk, sk);
    }
    else if (m->group == PQC_GROUP_MLKEM768)
    {
        ret = mlkem768_keypair(pk, sk);
    }
    else
    {
        ret = mlkem1024_keypair(pk, sk);
    }
    if (ret != 0)
    {
        os_free(sk);
        return ret;
    }
    m->sk = sk;
    return 0;
}

int pqc_mlkem_encaps(const pqc_mlkem *m, u8 *ct, u8 *ss, const u8 *pk)
{
    if (m->group == PQC_GROUP_MLKEM512)
    {
        return mlkem512_enc(ct, ss, pk);
    }
    if (m->group == PQC_GROUP_MLKEM768)
    {
        return mlkem768_enc(ct, ss, pk);
    }
    return mlkem1024_enc(ct, ss, pk);
}

int pqc_mlkem_decaps(const pqc_mlkem *m, u8 *ss, const u8 *ct)
{
    if (m->sk == NULL)
    {
        return -1;
    }
    if (m->group == PQC_GROUP_MLKEM512)
    {
        return mlkem512_dec(ss, ct, m->sk);
    }
    if (m->group == PQC_GROUP_MLKEM768)
    {
        return mlkem768_dec(ss, ct, m->sk);
    }
    return mlkem1024_dec(ss, ct, m->sk);
}

void pqc_mlkem_deinit(pqc_mlkem *m)
{
    if (m->sk != NULL)
    {
        bin_clear_free(m->sk, m->len_sk);
    }
    os_free(m);
}

pqc_tempo *pqc_tempo_init(int group)
{
    pqc_tempo *t = os_zalloc(sizeof(pqc_tempo));
    if (t == NULL)
    {
        return NULL;
    }
    if (group == PQC_GROUP_MLKEM512)
    {
        t->len_pk = TEMPO512_LEN_PUBLIC_KEY;
        t->len_sk = TEMPO512_LEN_SECRET_KEY;
        t->len_req = TEMPO512_LEN_REQ;
        t->len_res = TEMPO512_LEN_RES;
        t->len_tag = TEMPO512_LEN_TAG;
    }
    else if (group == PQC_GROUP_MLKEM768)
    {
        t->len_pk = TEMPO768_LEN_PUBLIC_KEY;
        t->len_sk = TEMPO768_LEN_SECRET_KEY;
        t->len_req = TEMPO768_LEN_REQ;
        t->len_res = TEMPO768_LEN_RES;
        t->len_tag = TEMPO768_LEN_TAG;
    }
    else if (group == PQC_GROUP_MLKEM1024)
    {
        t->len_pk = TEMPO1024_LEN_PUBLIC_KEY;
        t->len_sk = TEMPO1024_LEN_SECRET_KEY;
        t->len_req = TEMPO1024_LEN_REQ;
        t->len_res = TEMPO1024_LEN_RES;
        t->len_tag = TEMPO1024_LEN_TAG;
    }
    else
    {
        os_free(t);
        return NULL;
    }
    t->group = group;
    return t;
}

bool pqc_tempo_check_req(const pqc_tempo *t, const u8 *req)
{
    int ret;
    if (t->group == PQC_GROUP_MLKEM512)
    {
        ret = tempo512_check_req(req);
    }
    else if (t->group == PQC_GROUP_MLKEM768)
    {
        ret = tempo768_check_req(req);
    }
    else
    {
        ret = tempo1024_check_req(req);
    }
    return ret == 0;
}

int pqc_tempo_prepare(
    pqc_tempo *t,
    const u8 *own_addr,
    const u8 *peer_addr,
    const u8 *password,
    size_t password_len)
{
    u8 *sid = os_zalloc(TEMPO_LEN_SID);
    if (sid == NULL)
    {
        os_free(t);
        return -1;
    }
    if (os_memcmp(own_addr, peer_addr, ETH_ALEN) > 0)
    {
        os_memcpy(sid, own_addr, ETH_ALEN);
        os_memcpy(sid + ETH_ALEN, peer_addr, ETH_ALEN);
    }
    else
    {
        os_memcpy(sid, peer_addr, ETH_ALEN);
        os_memcpy(sid + ETH_ALEN, own_addr, ETH_ALEN);
    }
    u8 *pwd = os_malloc(TEMPO_LEN_PWD);
    if (pwd == NULL)
    {
        os_free(t);
        os_free(sid);
        return -1;
    }
    if (sha256_vector(1, &password, &password_len, pwd) != 0)
    {
        os_free(t);
        os_free(sid);
        os_free(pwd);
        return -1;
    }
    t->sid = sid;
    t->pwd = pwd;
    return 0;
}

int pqc_tempo_keygen(pqc_tempo *t, u8 *req)
{
    if (t->sid == NULL || t->pwd == NULL)
    {
        return -1;
    }
    u8 *pk = os_malloc(t->len_pk);
    if (pk == NULL)
    {
        return -1;
    }
    u8 *sk = os_malloc(t->len_sk);
    if (sk == NULL)
    {
        os_free(pk);
        return -1;
    }
    int ret;
    if (t->group == PQC_GROUP_MLKEM512)
    {
        ret = tempo512_keygen(req, pk, sk, t->sid, t->pwd);
    }
    else if (t->group == PQC_GROUP_MLKEM768)
    {
        ret = tempo768_keygen(req, pk, sk, t->sid, t->pwd);
    }
    else
    {
        ret = tempo1024_keygen(req, pk, sk, t->sid, t->pwd);
    }
    if (ret != 0)
    {
        os_free(pk);
        os_free(sk);
    }
    else
    {
        t->is_initiator = true;
        t->pk = pk;
        t->sk = sk;
    }
    return ret;
}

int pqc_tempo_encaps(pqc_tempo *t, u8 *res, const u8 *req)
{
    if (t->sid == NULL || t->pwd == NULL)
    {
        return -1;
    }
    u8 *pk = os_malloc(t->len_pk);
    if (pk == NULL)
    {
        return -1;
    }
    u8 *ss = os_malloc(TEMPO_LEN_SHARED_SECRET);
    if (ss == NULL)
    {
        os_free(pk);
        return -1;
    }
    int ret;
    if (t->group == PQC_GROUP_MLKEM512)
    {
        ret = tempo512_encaps(res, pk, ss, req, t->sid, t->pwd);
    }
    else if (t->group == PQC_GROUP_MLKEM768)
    {
        ret = tempo768_encaps(res, pk, ss, req, t->sid, t->pwd);
    }
    else
    {
        ret = tempo1024_encaps(res, pk, ss, req, t->sid, t->pwd);
    }
    if (ret != 0)
    {
        os_free(pk);
        os_free(ss);
    }
    else
    {
        t->pk = pk;
        t->ss = ss;
    }
    return ret;
}

int pqc_tempo_decaps(pqc_tempo *t, const u8 *res)
{
    if (t->sk == NULL)
    {
        return -1;
    }
    u8 *ss = os_malloc(TEMPO_LEN_SHARED_SECRET);
    if (ss == NULL)
    {
        return -1;
    }
    int ret;
    if (t->group == PQC_GROUP_MLKEM512)
    {
        ret = tempo512_decaps(ss, t->sk, res);
    }
    else if (t->group == PQC_GROUP_MLKEM768)
    {
        ret = tempo768_decaps(ss, t->sk, res);
    }
    else
    {
        ret = tempo1024_decaps(ss, t->sk, res);
    }
    if (ret != 0)
    {
        os_free(ss);
    }
    else
    {
        t->ss = ss;
    }
    return ret;
}

int pqc_tempo_confirm(
    const pqc_tempo *t,
    u8 *tag,
    const u8 *ctr,
    const u8 *req,
    const u8 *res)
{
    if (t->sid == NULL || t->pwd == NULL || t->pk == NULL || t->ss == NULL)
    {
        return -1;
    }
    if (t->group == PQC_GROUP_MLKEM512)
    {
        return tempo512_confirm(
            tag,
            t->is_initiator,
            ctr,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    if (t->group == PQC_GROUP_MLKEM768)
    {
        return tempo768_confirm(
            tag,
            t->is_initiator,
            ctr,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    return tempo1024_confirm(
        tag,
        t->is_initiator,
        ctr,
        t->pk,
        req,
        res,
        t->ss,
        t->sid,
        t->pwd);
}

int pqc_tempo_verify(
    const pqc_tempo *t,
    const u8 *peer_tag,
    const u8 *peer_ctr,
    const u8 *req,
    const u8 *res)
{
    if (t->sid == NULL || t->pwd == NULL || t->pk == NULL || t->ss == NULL)
    {
        return -1;
    }
    if (t->group == PQC_GROUP_MLKEM512)
    {
        return tempo512_verify(
            t->is_initiator,
            peer_tag,
            peer_ctr,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    if (t->group == PQC_GROUP_MLKEM768)
    {
        return tempo768_verify(
            t->is_initiator,
            peer_tag,
            peer_ctr,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    return tempo1024_verify(
        t->is_initiator,
        peer_tag,
        peer_ctr,
        t->pk,
        req,
        res,
        t->ss,
        t->sid,
        t->pwd);
}

int pqc_tempo_finish(
    const pqc_tempo *t,
    u8 *mk,
    u8 *mkid,
    const u8 *req,
    const u8 *res)
{
    if (t->sid == NULL || t->pwd == NULL || t->pk == NULL || t->ss == NULL)
    {
        return -1;
    }
    if (t->group == PQC_GROUP_MLKEM512)
    {
        return tempo512_finish(
            mk,
            mkid,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    if (t->group == PQC_GROUP_MLKEM768)
    {
        return tempo768_finish(
            mk,
            mkid,
            t->pk,
            req,
            res,
            t->ss,
            t->sid,
            t->pwd);
    }
    return tempo1024_finish(mk, mkid, t->pk, req, res, t->ss, t->sid, t->pwd);
}

void pqc_tempo_deinit(pqc_tempo *t)
{
    if (t->sid != NULL)
    {
        os_free(t->sid);
    }
    if (t->pwd != NULL)
    {
        bin_clear_free(t->pwd, TEMPO_LEN_PWD);
    }
    if (t->pk != NULL)
    {
        bin_clear_free(t->pk, t->len_pk);
    }
    if (t->sk != NULL)
    {
        bin_clear_free(t->sk, t->len_sk);
    }
    if (t->ss != NULL)
    {
        bin_clear_free(t->ss, TEMPO_LEN_SHARED_SECRET);
    }
    os_free(t);
}
