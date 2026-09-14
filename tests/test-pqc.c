#include <sys/random.h>
#include "crypto/pqc.h"

int mlkem_exchange(int group)
{
    pqc_mlkem *m1 = pqc_mlkem_init(group);
    if (m1 == NULL)
    {
        return -2;
    }
    pqc_mlkem *m2 = pqc_mlkem_init(group);
    if (m2 == NULL)
    {
        pqc_mlkem_deinit(m1);
        return -2;
    }
    u8 *pk = os_malloc(m1->len_pk);
    if (pk == NULL)
    {
        pqc_mlkem_deinit(m1);
        pqc_mlkem_deinit(m2);
        return -2;
    }
    u8 *ct = os_malloc(m2->len_ct);
    if (ct == NULL)
    {
        pqc_mlkem_deinit(m1);
        pqc_mlkem_deinit(m2);
        os_free(pk);
        return -2;
    }
    u8 *ss1 = os_malloc(PQC_MLKEM_LEN_SHARED_SECRET);
    if (ss1 == NULL)
    {
        pqc_mlkem_deinit(m1);
        pqc_mlkem_deinit(m2);
        os_free(pk);
        os_free(ct);
        return -2;
    }
    u8 *ss2 = os_malloc(PQC_MLKEM_LEN_SHARED_SECRET);
    if (ss2 == NULL)
    {
        pqc_mlkem_deinit(m1);
        pqc_mlkem_deinit(m2);
        os_free(pk);
        os_free(ct);
        os_free(ss1);
        return -2;
    }
    int ret = 0;
    if (pqc_mlkem_keygen(m1, pk) != 0 ||
        pqc_mlkem_encaps(m2, ct, ss2, pk) != 0 ||
        pqc_mlkem_decaps(m1, ss1, ct) != 0 ||
        os_memcmp(ss1, ss2, PQC_MLKEM_LEN_SHARED_SECRET) != 0)
    {
        ret = -1;
    }
    pqc_mlkem_deinit(m1);
    pqc_mlkem_deinit(m2);
    os_free(pk);
    os_free(ct);
    os_free(ss1);
    os_free(ss2);
    return ret;
}

int tempo_exchange(int group, const u8 *pwd1, const u8 *pwd2)
{
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    if (getrandom(addr1, ETH_ALEN, GRND_NONBLOCK) == -1 ||
        getrandom(addr2, ETH_ALEN, GRND_NONBLOCK) == -1)
    {
        return -2;
    }
    u8 ctr1[2];
    u8 ctr2[2];
    ctr1[0] = 0;
    ctr1[1] = 0;
    ctr2[0] = 0xFF;
    ctr2[1] = 0xFF;
    pqc_tempo *t1 = pqc_tempo_init(group, addr1, addr2, pwd1, 12);
    if (t1 == NULL)
    {
        return -2;
    }
    pqc_tempo *t2 = pqc_tempo_init(group, addr2, addr1, pwd2, 12);
    if (t2 == NULL)
    {
        pqc_tempo_deinit(t1);
        return -2;
    }
    u8 *req = os_malloc(t1->len_req);
    if (req == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        return -2;
    }
    u8 *res = os_malloc(t2->len_res);
    if (res == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        os_free(req);
        return -2;
    }
    u8 *tag1 = os_malloc(t1->len_tag);
    if (tag1 == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        os_free(req);
        os_free(res);
        return -2;
    }
    u8 *tag2 = os_malloc(t2->len_tag);
    if (tag2 == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        os_free(req);
        os_free(res);
        os_free(tag1);
        return -2;
    }
    u8 *mk1 = os_malloc(PQC_TEMPO_LEN_MASTER_KEY);
    if (mk1 == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        os_free(req);
        os_free(res);
        os_free(tag1);
        os_free(tag2);
        return -2;
    }
    u8 *mk2 = os_malloc(PQC_TEMPO_LEN_MASTER_KEY);
    if (mk2 == NULL)
    {
        pqc_tempo_deinit(t1);
        pqc_tempo_deinit(t2);
        os_free(req);
        os_free(res);
        os_free(tag1);
        os_free(tag2);
        os_free(mk1);
        return -2;
    }
    int ret = 0;
    if (pqc_tempo_keygen(t1, req) != 0 ||
        pqc_tempo_encaps(t2, res, req) != 0 ||
        pqc_tempo_decaps(t1, res) != 0 ||
        pqc_tempo_confirm(t1, tag1, ctr1) != 0 ||
        pqc_tempo_confirm(t2, tag2, ctr2) != 0 ||
        pqc_tempo_verify(t1, tag2, ctr2) != 1 ||
        pqc_tempo_verify(t2, tag1, ctr1) != 1 ||
        pqc_tempo_finish(t1, mk1) != 0 ||
        pqc_tempo_finish(t2, mk2) != 0 ||
        os_memcmp(mk1, mk2, PQC_TEMPO_LEN_MASTER_KEY) != 0)
    {
        ret = -1;
    }
    pqc_tempo_deinit(t1);
    pqc_tempo_deinit(t2);
    os_free(req);
    os_free(res);
    os_free(tag1);
    os_free(tag2);
    os_free(mk1);
    os_free(mk2);
    return ret;
}

int tempo_exchange_correct(int group)
{
    u8 pwd[12];
    if (getrandom(pwd, 12, GRND_NONBLOCK) == -1)
    {
        return -2;
    }
    return tempo_exchange(group, pwd, pwd);
}

int tempo_exchange_incorrect(int group)
{
    u8 pwd1[12];
    u8 pwd2[12];
    if (getrandom(pwd1, 12, GRND_NONBLOCK) == -1 ||
        getrandom(pwd2, 12, GRND_NONBLOCK) == -1)
    {
        return -2;
    }
    int ret = tempo_exchange(group, pwd1, pwd2);
    if (ret == 0)
    {
        return -1;
    }
    if (ret == -1)
    {
        return 0;
    }
    return ret;
}

int main()
{
    int groups[] = {
        PQC_GROUP_MLKEM512,
        PQC_GROUP_MLKEM768,
        PQC_GROUP_MLKEM1024,
    };
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 1000; j++)
        {
            if (mlkem_exchange(groups[i]) != 0)
            {
                return EXIT_FAILURE;
            }
            if (tempo_exchange_correct(groups[i]) != 0)
            {
                return EXIT_FAILURE;
            }
            if (tempo_exchange_incorrect(groups[i]) != 0)
            {
                return EXIT_FAILURE;
            }
        }
    }
    return EXIT_SUCCESS;
}
