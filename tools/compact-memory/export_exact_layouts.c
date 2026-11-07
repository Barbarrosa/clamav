/* SPDX-License-Identifier: GPL-2.0-only
 * Trusted-input diagnostic: export exact scalar fields and ordered link IDs.
 * The original engine remains the oracle. This is not a production file format.
 */
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "require_ac_directories.h"

#ifndef CLI_AC_FLAT_NODES
#error "Requires the matching flat-node engine"
#endif
#define NIL UINT32_MAX
struct ref { const void *ptr; uint32_t id; };
static const char **names;
static size_t name_count, name_cap;
static void *allocate(size_t n) { void *p=malloc(n?n:1); if(!p) abort(); return p; }
static int ptrcmp(const void *a,const void *b) {
    uintptr_t x=(uintptr_t)((const struct ref *)a)->ptr,y=(uintptr_t)((const struct ref *)b)->ptr;
    return (x>y)-(x<y);
}
static uint32_t reference(const struct ref *refs,size_t n,const void *p) {
    if(!p) return NIL;
    struct ref key={p,0}; const struct ref *r=bsearch(&key,refs,n,sizeof(*refs),ptrcmp);
    if(!r || r->ptr!=p) abort();
    return r->id;
}
static int namecmp(const void *a,const void *b) {return strcmp(*(const char *const *)a,*(const char *const *)b);}
static void addname(const char *s) {
    if(!s) return;
    if(name_count==name_cap) {name_cap=name_cap?name_cap*2:4096; names=realloc(names,name_cap*sizeof(*names)); if(!names) abort();}
    names[name_count++]=s;
}
static uint32_t nameid(const char *s) {
    if(!s) return NIL;
    const char **p=bsearch(&s,names,name_count,sizeof(*names),namecmp);
    if(!p || strcmp(*p,s)) abort();
    return (uint32_t)(p-names);
}
static void hash_names(const struct cli_matcher *r) {
    if(!r) return;
    for(unsigned t=0;t<CLI_HASH_AVAIL_TYPES;t++) {
        if(r->hm.compiled) {
            const struct cli_hash_compiled *g=&r->hm.compiled[t];
            for(size_t j=0;j<g->items;j++) addname(cli_hm_compiled_name(g,j));
            continue;
        }
        const struct cli_htu32 *ht=&r->hm.sizehashes[t];
        for(size_t i=0;i<ht->capacity;i++) {
            if(!ht->htable[i].key || ht->htable[i].key==UINT32_MAX) continue;
            const struct cli_sz_hash *s=ht->htable[i].data.as_ptr;
            for(uint32_t j=0;j<s->items;j++) addname(s->virusnames[j]);
        }
        const struct cli_sz_hash *s=&r->hwild.hashes[t];
        for(uint32_t j=0;j<s->items;j++) addname(s->virusnames[j]);
    }
}
static FILE *output(const char *dir,const char *name) {
    char path[4096]; int n=snprintf(path,sizeof(path),"%s/%s",dir,name);
    if(n<0 || (size_t)n>=sizeof(path)) abort();
    FILE *f=fopen(path,"wb"); if(!f) {perror(path);abort();} return f;
}
static void put(FILE *f,uint32_t v,unsigned width) {
    unsigned char b[4]={v,v>>8,v>>16,v>>24}; if(fwrite(b,1,width,f)!=width) abort();
}
static uint32_t nodeid(const struct cli_matcher *r,const struct cli_ac_node *p,uint32_t base) {
    if(!p) return NIL;
    ptrdiff_t d=p-r->ac_flatnodes;
    if(d<1 || (size_t)d>(size_t)r->ac_nodes+1) abort();
    return base+(uint32_t)d-1;
}
static int coordinate(const struct cli_lsig_tdb *d,const uint32_t *p,uint32_t *id) {
    if(!p){*id=NIL;return 1;}
    const uint32_t *bases[2]={d->val,d->range};
    size_t counts[2]={d->cnt[CLI_TDB_UINT],(size_t)d->cnt[CLI_TDB_RANGE]};
    for(unsigned b=0;b<2;b++) {
        uintptr_t a=(uintptr_t)p,start=(uintptr_t)bases[b];
        if(bases[b] && a>=start && a-start<counts[b]*4 && !((a-start)%4)) {
            *id=(uint32_t)((a-start)/4)|(b?UINT32_C(0x80000000):0);return 1;
        }
    }
    return 0;
}
static int template(const struct cli_lsig_tdb *d,FILE *f) {
    if(d->str || d->cnt[CLI_TDB_STR] || d->icongrp1 || d->icongrp2 || d->intermediates || d->macro_ptids ||
       (!!d->val != !!d->cnt[CLI_TDB_UINT]) || (!!d->range != !!d->cnt[CLI_TDB_RANGE])) {put(f,0,4);return 0;}
    const uint32_t *p[7]={d->target,d->engine,d->nos,d->ep,d->filesize,d->container,d->handlertype};
    uint32_t ref[7];for(unsigned i=0;i<7;i++)if(!coordinate(d,p[i],&ref[i])){put(f,0,4);return 0;}
    size_t n=(size_t)d->cnt[CLI_TDB_UINT]+(size_t)d->cnt[CLI_TDB_RANGE];
    if(n>(UINT32_MAX/4)-11)abort();
    put(f,(11+n)*4,4);
    put(f,d->subsigs,4);for(unsigned i=0;i<3;i++)put(f,d->cnt[i],4);
    for(unsigned i=0;i<7;i++) {
        put(f,ref[i],4);
        if(ref[i]!=NIL) {
            const uint32_t *restored=(ref[i]>>31?d->range:d->val)+(ref[i]&0x7fffffff);
            if(restored!=p[i])abort();
        }
    }
    for(size_t i=0;i<(size_t)d->cnt[CLI_TDB_UINT];i++)put(f,d->val[i],4);
    for(size_t i=0;i<(size_t)d->cnt[CLI_TDB_RANGE];i++)put(f,d->range[i],4);
    return 1;
}
int main(int argc,char **argv) {
    if(argc!=4 || cl_init(CL_INIT_DEFAULT)) return 1;
    struct cl_engine *e=cl_engine_new(); unsigned sigs=0;
    if(!e || cl_engine_set_str(e,CL_ENGINE_CVDCERTSDIR,argv[2]) ||
       cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1) || cl_load(argv[1],e,&sigs,CL_DB_STDOPT) || cl_engine_compile(e)) return 2;
    if (!cm_require_ac_directories(e)) return 8;
    size_t np=0,nl=0,ne=0,nn=0,nlogic=0;
    for(unsigned t=0;t<CLI_MTARGETS;t++) {
        struct cli_matcher *r=e->root[t]; if(!r) continue;
        np+=r->ac_patterns; nl+=r->ac_lists;nlogic+=r->ac_lsigs;
        if(r->ac_root) nn+=(size_t)r->ac_nodes+1;
        for(uint32_t j=0;j<r->ac_patterns;j++) {addname(r->ac_pattable[j]->virname); if(r->ac_pattable[j]->ext) ne++;}
        for(uint32_t j=0;j<r->ac_lsigs;j++) addname(r->ac_lsigtable[j]->virname);
    }
    hash_names(e->hm_hdb);hash_names(e->hm_mdb);hash_names(e->hm_imp);hash_names(e->hm_fp);
    qsort(names,name_count,sizeof(*names),namecmp);
    size_t unique=0; for(size_t i=0;i<name_count;i++) if(!i || strcmp(names[i],names[i-1])) names[unique++]=names[i];
    name_count=unique;
    if(np>=NIL || nl>=NIL || ne>=NIL || nn>=NIL || name_count>=NIL || nlogic>=UINT32_C(0x80000000)) return 3;
    struct ref *pr=allocate(np*sizeof(*pr)),*lr=allocate(nl*sizeof(*lr)),*er=allocate(ne*sizeof(*er));
    size_t pi=0,li=0,ei=0;
    for(unsigned t=0;t<CLI_MTARGETS;t++) {
        struct cli_matcher *r=e->root[t]; if(!r) continue;
        for(uint32_t j=0;j<r->ac_patterns;j++,pi++) {pr[pi]=(struct ref){r->ac_pattable[j],pi}; if(r->ac_pattable[j]->ext) {er[ei]=(struct ref){r->ac_pattable[j]->ext,ei}; ei++;}}
        for(uint32_t j=0;j<r->ac_lists;j++,li++) lr[li]=(struct ref){r->ac_listtable[j],li};
    }
    qsort(pr,np,sizeof(*pr),ptrcmp);qsort(lr,nl,sizeof(*lr),ptrcmp);qsort(er,ne,sizeof(*er),ptrcmp);
    /* Extension IDs preserve pointer identity, including any shared extension. */
    unique=0; for(size_t i=0;i<ne;i++) if(!i || er[i].ptr!=er[i-1].ptr) er[unique++]=er[i];
    ne=unique; for(size_t i=0;i<ne;i++) er[i].id=i;
    FILE *pf=output(argv[3],"patterns.bin"),*lf=output(argv[3],"links.bin"),*nf=output(argv[3],"nodes.bin"),
         *tf=output(argv[3],"tokens.bin"),*namesf=output(argv[3],"names.bin"),
         *lg=output(argv[3],"logical.bin"),*td=output(argv[3],"templates.bin"),*pg=output(argv[3],"programs.bin");
    uint64_t namebytes=0,tokenbytes=0,logical_aux=0,escape_aux=0; pi=0;li=0;uint32_t nodebase=0,logicid=0,td_escapes=0,code_escapes=0;
    for(size_t i=0;i<name_count;i++) {size_t n=strlen(names[i]);if(n>UINT32_MAX) abort();put(namesf,n,4);if(fwrite(names[i],1,n,namesf)!=n) abort();namebytes+=n+1;}
    for(unsigned t=0;t<CLI_MTARGETS;t++) {
        struct cli_matcher *r=e->root[t];if(!r) continue;
        for(uint32_t j=0;j<r->ac_lsigs;j++,logicid++) {
            const struct cli_ac_lsig *l=r->ac_lsigtable[j];uint32_t program=logicid;
            size_t aux=((size_t)l->tdb.cnt[CLI_TDB_UINT]+(size_t)l->tdb.cnt[CLI_TDB_RANGE])*4;
            logical_aux+=aux;
            if(l->type==CLI_LSIG_NORMAL && l->u.logic) {
                size_t n=strlen(l->u.logic);logical_aux+=n+1;if(n>=NIL)abort();put(pg,n+1,4);if(fwrite(l->u.logic,1,n+1,pg)!=n+1)abort();
            } else {program=UINT32_C(0x80000000)|code_escapes++;put(pg,0,4);}
            uint32_t tdb=logicid;
            if(!template(&l->tdb,td)){tdb=UINT32_C(0x80000000)|td_escapes++;escape_aux+=aux;}
            uint32_t values[7]={l->id,l->bc_idx,l->type,l->flag,nameid(l->virname),program,tdb};
            for(unsigned k=0;k<7;k++)put(lg,values[k],4);
        }
        for(uint32_t j=0;j<r->ac_patterns;j++,pi++) {
            const struct cli_ac_patt *p=r->ac_pattable[j];
            uint32_t v[13]={(uint32_t)pi,nameid(p->virname),reference(er,ne,p->ext),p->sigid,
                p->lsigid[0],p->lsigid[1],p->lsigid[2],p->offdata[0],p->offdata[1],p->offdata[2],p->offdata[3],p->offset_min,p->offset_max};
            uint16_t w[10]={p->length[0],p->length[1],p->length[2],p->prefix_length[0],p->prefix_length[1],p->prefix_length[2],p->parts,p->partno,p->rtype,p->type};
            if(reference(pr,np,p)!=pi) abort();
            for(unsigned k=0;k<13;k++) put(pf,v[k],4);
            for(unsigned k=0;k<10;k++) put(pf,w[k],2);
            put(pf,p->depth,1);put(pf,p->sigopts,1);
            uint32_t count=(uint32_t)p->length[0]+p->prefix_length[0]; put(tf,count,4);
            for(uint32_t k=0;k<count;k++) put(tf,k<p->prefix_length[0]?p->prefix[k]:p->pattern[k-p->prefix_length[0]],2);
            tokenbytes+=(uint64_t)count*2;
        }
        for(uint32_t j=0;j<r->ac_lists;j++,li++) {
            const struct cli_ac_list *p=r->ac_listtable[j];if(reference(lr,nl,p)!=li) abort();
            put(lf,reference(pr,np,p->me),4);put(lf,reference(lr,nl,p->next),4);put(lf,reference(lr,nl,p->next_same),4);
        }
        if(r->ac_root) {
            if(!r->ac_flatnodes) {
                if(r->ac_nodes || (r->ac_root->fail && r->ac_root->fail!=r->ac_root)) abort();
                put(nf,reference(lr,nl,r->ac_root->list),4);
                put(nf,r->ac_root->fail?nodebase:NIL,4);
            } else for(uint32_t s=1;s<=r->ac_nodes+1;s++) {
                const struct cli_ac_node *p=r->ac_flatnodes+s;
                put(nf,reference(lr,nl,p->list),4);put(nf,nodeid(r,p->fail,nodebase),4);
            }
            nodebase+=r->ac_nodes+1;
        }
    }
    if(fclose(pf)||fclose(lf)||fclose(nf)||fclose(tf)||fclose(namesf)||fclose(lg)||fclose(td)||fclose(pg)) abort();
    printf("{\"kind\":\"logical_export\",\"records\":%zu,\"original_record_and_directory_bytes\":%zu,\"target_template_escapes\":%u,\"conservative_escape_record_bytes\":%zu,\"code_pointer_escapes\":%u,\"code_pointer_directory_bytes\":%zu,\"all_template_coordinates_verified\":true}\n",nlogic,nlogic*(sizeof(struct cli_ac_lsig)+sizeof(void *)),td_escapes,(size_t)td_escapes*(sizeof(struct cli_ac_lsig)+sizeof(void *)),code_escapes,(size_t)code_escapes*sizeof(void *));
    printf("{\"kind\":\"logical_auxiliary\",\"original_known_auxiliary_bytes\":%llu,\"retained_escape_value_bytes\":%llu}\n",(unsigned long long)logical_aux,(unsigned long long)escape_aux);
    printf("{\"signatures\":%u,\"patterns\":%zu,\"links\":%zu,\"nodes\":%zu,\"names\":%zu,\"extensions\":%zu,\"raw_name_bytes\":%llu,\"token_bytes\":%llu,\"pattern_record_bytes\":74,\"original_pattern_and_directory_bytes\":%zu,\"original_link_and_directory_bytes\":%zu,\"extension_pointer_directory_bytes\":%zu,\"all_references_checked\":true}\n",sigs,np,nl,nn,name_count,ne,(unsigned long long)namebytes,(unsigned long long)tokenbytes,np*(sizeof(struct cli_ac_patt)+sizeof(void *)),nl*(sizeof(struct cli_ac_list)+sizeof(void *)),ne*sizeof(void *));
    free(pr);free(lr);free(er);free(names);cl_engine_free(e);return 0;
}
