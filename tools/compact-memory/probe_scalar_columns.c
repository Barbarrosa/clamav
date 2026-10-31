/* SPDX-License-Identifier: GPL-2.0-only
 * Exact, bounded-access scalar columns: constant, affine, frame-of-reference,
 * or bitmap-ranked exceptions. Raw mode remains a separate performance path.
 * Standalone representation diagnostic; no ClamAV scanner integration.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

enum { CONSTANT, FRAME, EXCEPTIONS, AFFINE };
struct column { uint32_t base, offset; uint16_t count; uint8_t mode, bits; };
struct store { struct column *columns; unsigned char *payload; size_t bytes, rows, blocks; unsigned group, fields, stride, width[32], field_offset[32]; size_t modes[4]; };
static void *memory(size_t n) {void *p=calloc(n?n:1,1);if(!p)abort();return p;}
static uint32_t u32(const void *p) {uint32_t x;memcpy(&x,p,4);return x;}
static uint16_t u16(const void *p) {uint16_t x;memcpy(&x,p,2);return x;}
static uint64_t u64(const void *p) {uint64_t x;memcpy(&x,p,8);return x;}
static uint32_t raw_value(const struct store *s,const unsigned char *raw,size_t row,unsigned c) {
    const unsigned char *p=raw+row*s->stride+s->field_offset[c];
    return s->width[c]==4?u32(p):s->width[c]==2?u16(p):*p;
}
static unsigned width32(uint32_t v) {return v?32-__builtin_clz(v):0;}
static int compare(const void *a,const void *b) {uint32_t x=u32(a),y=u32(b);return (x>y)-(x<y);}
static void destroy(struct store *s) {free(s->columns);free(s->payload);s->columns=NULL;s->payload=NULL;}
static int build(struct store *s,const unsigned char *raw,size_t bytes,unsigned group) {
    if(!s->stride || bytes%s->stride || group<1 || group>1024 || !bytes) return 0;
    s->rows=bytes/s->stride;s->group=group;s->blocks=(s->rows+group-1)/group;
    if(s->blocks>SIZE_MAX/s->fields/sizeof(struct column) || s->rows>SIZE_MAX/4/s->fields) return 0;
    s->columns=memory(s->blocks*s->fields*sizeof(struct column));
    size_t capacity=s->rows*s->fields*4+8; if(capacity>UINT32_MAX) return 0;
    s->payload=memory(capacity);s->bytes=0;
    uint32_t *v=memory(group*4),*sorted=memory(group*4);
    for(size_t b=0;b<s->blocks;b++) {
        size_t start=b*group;unsigned n=s->rows-start;if(n>group)n=group;
        for(unsigned c=0;c<s->fields;c++) {
            struct column *h=&s->columns[b*s->fields+c];
            uint32_t lo=UINT32_MAX,hi=0;unsigned affine=1;
            for(unsigned i=0;i<n;i++) {v[i]=raw_value(s,raw,start+i,c);sorted[i]=v[i];if(v[i]<lo)lo=v[i];if(v[i]>hi)hi=v[i];if(v[i]!=(uint32_t)(v[0]+i))affine=0;}
            h->offset=s->bytes;h->base=lo;h->bits=width32(hi-lo);h->mode=FRAME;
            size_t amount=((size_t)n*h->bits+7)/8;
            if(lo==hi) {h->mode=CONSTANT;amount=0;}
            else if(affine) {h->mode=AFFINE;h->base=v[0];amount=0;}
            else {
                qsort(sorted,n,4,compare);uint32_t common=sorted[0];unsigned best=1,run=1;
                for(unsigned i=1;i<n;i++) {run=sorted[i]==sorted[i-1]?run+1:1;if(run>best){best=run;common=sorted[i];}}
                unsigned exceptions=n-best,words=(n+63)/64;
                size_t sparse=(size_t)words*10+(size_t)exceptions*4;
                if(sparse<amount) {h->mode=EXCEPTIONS;h->base=common;h->count=exceptions;amount=sparse;}
            }
            if(amount>capacity-8-s->bytes) abort();
            unsigned char *p=s->payload+s->bytes;
            if(h->mode==FRAME) {
                for(unsigned i=0;i<n;i++) {
                    size_t bit=(size_t)i*h->bits;uint64_t x=(uint64_t)(v[i]-lo)<<(bit&7);
                    for(unsigned k=0;k<(h->bits+(bit&7)+7)/8;k++) p[bit/8+k]|=(unsigned char)(x>>(8*k));
                }
            } else if(h->mode==EXCEPTIONS) {
                unsigned words=(n+63)/64,rank=0;
                for(unsigned w=0;w<words;w++) {
                    uint64_t bits=0;uint16_t prefix=rank;memcpy(p+words*8+w*2,&prefix,2);
                    for(unsigned j=0;j<64 && w*64+j<n;j++) if(v[w*64+j]!=h->base) {
                        bits|=UINT64_C(1)<<j;memcpy(p+words*10+rank*4,&v[w*64+j],4);rank++;
                    }
                    memcpy(p+w*8,&bits,8);
                }
                if(rank!=h->count) abort();
            }
            s->modes[h->mode]++;s->bytes+=amount;
        }
    }
    free(v);free(sorted);
    void *p=realloc(s->payload,s->bytes+8);if(!p)abort();s->payload=p;memset(s->payload+s->bytes,0,8);return 1;
}
static int get(const struct store *s,size_t row,unsigned c,uint32_t *value) {
    if(row>=s->rows || c>=s->fields)return 0;
    size_t b=row/s->group;unsigned i=row%s->group,n=s->rows-b*s->group;if(n>s->group)n=s->group;
    const struct column *h=&s->columns[b*s->fields+c];
    if(h->offset>s->bytes)return 0;
    const unsigned char *p=s->payload+h->offset;
    if(h->mode==CONSTANT) {*value=h->base;return 1;}
    if(h->mode==AFFINE) {*value=h->base+i;return 1;}
    if(h->mode==FRAME) {
        if(!h->bits || h->bits>32 || ((size_t)n*h->bits+7)/8>s->bytes-h->offset)return 0;
        size_t bit=(size_t)i*h->bits;uint64_t mask=(UINT64_C(1)<<h->bits)-1;
        *value=h->base+(uint32_t)((u64(p+bit/8)>>(bit&7))&mask);return 1;
    }
    if(h->mode==EXCEPTIONS) {
        unsigned words=(n+63)/64;
        if(h->count>n || words*10+(size_t)h->count*4>s->bytes-h->offset)return 0;
        uint64_t bits=u64(p+(i/64)*8),mask=UINT64_C(1)<<(i%64);
        if(!(bits&mask)){*value=h->base;return 1;}
        unsigned rank=u16(p+words*8+(i/64)*2)+__builtin_popcountll(bits&(mask-1));
        if(rank>=h->count)return 0;
        *value=u32(p+words*10+rank*4);return 1;
    }
    return 0;
}
static void schema(struct store *s,const char *name) {
    if(!strcmp(name,"patterns")) {s->fields=25;for(unsigned c=0;c<25;c++)s->width[c]=c<13?4:c<23?2:1;}
    else if(!strcmp(name,"links")) {s->fields=3;for(unsigned c=0;c<3;c++)s->width[c]=4;}
    else if(!strcmp(name,"nodes")) {s->fields=2;s->width[0]=s->width[1]=4;}
    else if(!strcmp(name,"logical")) {s->fields=7;for(unsigned c=0;c<7;c++)s->width[c]=4;}
    else abort();
    for(unsigned c=0;c<s->fields;c++){s->field_offset[c]=s->stride;s->stride+=s->width[c];}
}
static uint64_t rng(uint64_t *s) {*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static volatile uint64_t sink;
static double run(const struct store *s,const unsigned char *raw,const uint32_t *query,size_t count,int packed) {
    uint64_t sum=0;double start=now();
    for(size_t i=0;i<count;i++) for(unsigned c=0;c<s->fields;c++) {uint32_t v;if(packed){if(!get(s,query[i],c,&v))abort();}else v=raw_value(s,raw,query[i],c);sum+=v;}
    sink=sum;return now()-start;
}
static void verify(const struct store *s,const unsigned char *raw) {
    for(size_t i=0;i<s->rows;i++)for(unsigned c=0;c<s->fields;c++){uint32_t v;if(!get(s,i,c,&v)||v!=raw_value(s,raw,i,c))abort();}
    uint32_t x;if(get(s,s->rows,0,&x)||get(s,0,s->fields,&x))abort();
}
static void selftest(void) {
    unsigned widths[]={1,2,63,64,65,128,256,1024};
    struct store base={0};schema(&base,"patterns");size_t count=1103;unsigned char *raw=memory(count*base.stride);uint64_t seed=261027;
    for(size_t i=0;i<count;i++)for(unsigned c=0;c<base.fields;c++){
        uint32_t value=c%4==0?UINT32_MAX:c%4==1?(uint32_t)(UINT32_MAX-500+i):c%4==2?(i%97?0xfffffffe:rng(&seed)):(uint32_t)rng(&seed);
        memcpy(raw+i*base.stride+base.field_offset[c],&value,base.width[c]);
    }
    for(unsigned j=0;j<sizeof(widths)/sizeof(*widths);j++) {
        struct store s=base;if(!build(&s,raw,count*s.stride,widths[j]))abort();verify(&s,raw);
        uint32_t x;struct column saved=s.columns[0];s.columns[0].offset=UINT32_MAX;if(get(&s,0,0,&x))abort();s.columns[0]=saved;
        s.columns[0].mode=255;if(get(&s,0,0,&x))abort();s.columns[0]=saved;destroy(&s);
    }
    free(raw);puts("{\"selftest\":\"passed\",\"boundary_block_sizes\":8,\"records_per_case\":1103,\"invalid_access_rejected\":true}");
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--selftest")){selftest();return 0;}
    if(argc!=4){fprintf(stderr,"usage: %s FILE patterns|links|nodes GROUP\n",argv[0]);return 1;}
    struct store s={0};schema(&s,argv[2]);unsigned group=strtoul(argv[3],NULL,10);
    FILE *f=fopen(argv[1],"rb");if(!f)return 2;if(fseek(f,0,SEEK_END))return 2;long length=ftell(f);if(length<=0)return 2;rewind(f);
    unsigned char *raw=memory(length);if(fread(raw,1,length,f)!=(size_t)length)return 2;fclose(f);
    double start=now();if(!build(&s,raw,length,group))return 3;double build_seconds=now()-start;verify(&s,raw);
    printf("{\"kind\":\"scalar_layout\",\"schema\":\"%s\",\"group\":%u,\"rows\":%zu,\"fields\":%u,\"raw_normalized_bytes\":%ld,\"encoded_payload_bytes\":%zu,\"directory_bytes\":%zu,\"total_bytes\":%zu,\"modes\":[%zu,%zu,%zu,%zu],\"build_seconds\":%.9f,\"all_fields_verified\":true}\n",argv[2],group,s.rows,s.fields,length,s.bytes,s.blocks*s.fields*sizeof(struct column),s.bytes+8+s.blocks*s.fields*sizeof(struct column)+sizeof(s),s.modes[0],s.modes[1],s.modes[2],s.modes[3],build_seconds);
    fflush(stdout);size_t count=1u<<17;uint32_t *query=memory(count*4);uint64_t seed=261027;
    for(unsigned kind=0;kind<3;kind++) {
        for(size_t i=0;i<count;i++)query[i]=kind==0?rng(&seed)%s.rows:kind==1?i%s.rows:i%(s.rows<32?s.rows:32);
        for(unsigned trial=0;trial<8;trial++){
            double times[2];uint64_t sums[2];for(unsigned order=0;order<2;order++){unsigned mode=order^(trial&1);times[mode]=run(&s,raw,query,count,mode);sums[mode]=sink;}
            if(sums[0]!=sums[1])abort();
            printf("{\"kind\":\"scalar_timing\",\"schema\":\"%s\",\"group\":%u,\"input\":%u,\"trial\":%u,\"queries\":%zu,\"raw_seconds\":%.9f,\"packed_seconds\":%.9f}\n",argv[2],group,kind,trial,count,times[0],times[1]);
        }
    }
    free(query);free(raw);destroy(&s);return 0;
}
