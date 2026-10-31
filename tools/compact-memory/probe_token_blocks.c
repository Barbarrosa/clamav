/* SPDX-License-Identifier: GPL-2.0-only
 * Exact token block store with bounded direct-mapped decoded cache and raw mode.
 * Uses checksummed Zstd frames, exact decoded lengths and bounded output buffers.
 * Standalone diagnostic, not a scanner integration or an engine RSS measurement.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zstd.h>

struct block {size_t offset;uint32_t length,decoded;unsigned raw;};
struct store {struct block *blocks;unsigned char *data,*cache;size_t size,raw_size,count,blocksize,slots,*cached,hits,misses;ZSTD_DCtx *decoder;};
static void *memory(size_t n){void *p=calloc(n?n:1,1);if(!p)abort();return p;}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static uint64_t rng(uint64_t *s){*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
static void clear(struct store *s){for(size_t i=0;i<s->slots;i++)s->cached[i]=SIZE_MAX;s->hits=s->misses=0;}
static int build(struct store *s,const unsigned char *input,size_t length,size_t blocksize,size_t cachebytes,int level){
    if(!length || blocksize<4096 || blocksize>1u<<20 || cachebytes<blocksize)return 0;
    s->raw_size=length;s->blocksize=blocksize;s->count=(length+blocksize-1)/blocksize;s->slots=cachebytes/blocksize;
    s->blocks=memory(s->count*sizeof(*s->blocks));s->data=memory(length);s->cache=memory(s->slots*blocksize);s->cached=memory(s->slots*sizeof(size_t));
    s->decoder=ZSTD_createDCtx();ZSTD_CCtx *encoder=ZSTD_createCCtx();if(!s->decoder||!encoder)return 0;
    if(ZSTD_isError(ZSTD_DCtx_setParameter(s->decoder,ZSTD_d_windowLogMax,20)) ||
       ZSTD_isError(ZSTD_CCtx_setParameter(encoder,ZSTD_c_compressionLevel,level)) ||
       ZSTD_isError(ZSTD_CCtx_setParameter(encoder,ZSTD_c_checksumFlag,1)))return 0;
    size_t capacity=ZSTD_compressBound(blocksize);unsigned char *temp=memory(capacity);
    for(size_t b=0;b<s->count;b++){
        size_t n=length-b*blocksize;if(n>blocksize)n=blocksize;
        size_t c=ZSTD_compress2(encoder,temp,capacity,input+b*blocksize,n);if(ZSTD_isError(c))return 0;
        struct block *p=&s->blocks[b];p->offset=s->size;p->decoded=n;p->raw=c>=n;p->length=p->raw?n:c;
        memcpy(s->data+s->size,p->raw?input+b*blocksize:temp,p->length);s->size+=p->length;
    }
    free(temp);ZSTD_freeCCtx(encoder);void *p=realloc(s->data,s->size);if(!p)return 0;s->data=p;clear(s);return 1;
}
static const unsigned char *block(struct store *s,size_t id){
    if(id>=s->count)return NULL;
    const struct block *b=&s->blocks[id];
    size_t expected=s->raw_size-id*s->blocksize;if(expected>s->blocksize)expected=s->blocksize;
    if(b->offset>s->size || b->length>s->size-b->offset || !b->decoded || b->decoded!=expected || b->raw>1)return NULL;
    const unsigned char *input=s->data+b->offset;
    if(b->raw){if(b->length!=b->decoded)return NULL;s->hits++;return input;}
    size_t slot=id%s->slots;
    if(s->cached[slot]==id){s->hits++;return s->cache+slot*s->blocksize;}
    s->misses++;s->cached[slot]=SIZE_MAX;
    if(ZSTD_getFrameContentSize(input,b->length)!=b->decoded)return NULL;
    unsigned char *output=s->cache+slot*s->blocksize;
    size_t n=ZSTD_decompressDCtx(s->decoder,output,s->blocksize,input,b->length);
    if(ZSTD_isError(n)||n!=b->decoded)return NULL;
    s->cached[slot]=id;return output;
}
static int read_bytes(struct store *s,size_t length,size_t offset,size_t count,unsigned char *out){
    if(length!=s->raw_size||offset>length||count>length-offset)return 0;
    while(count){size_t id=offset/s->blocksize,local=offset%s->blocksize;const unsigned char *p=block(s,id);if(!p)return 0;
        size_t n=s->blocks[id].decoded-local;if(n>count)n=count;memcpy(out,p+local,n);offset+=n;out+=n;count-=n;}
    return 1;
}
static unsigned char *file(const char *path,size_t *size){FILE *f=fopen(path,"rb");if(!f)abort();if(fseek(f,0,SEEK_END))abort();long n=ftell(f);if(n<=0)abort();rewind(f);unsigned char *p=memory(n);if(fread(p,1,n,f)!=(size_t)n)abort();fclose(f);*size=n;return p;}
static volatile uint64_t sink;
static double lookup(struct store *s,const unsigned char *raw,size_t length,const uint32_t *index,const uint32_t *queries,size_t count,unsigned char *scratch,int packed){
    uint64_t sum=0;double start=now();
    for(size_t i=0;i<count;i++){uint32_t id=queries[i];size_t off=index[id]&0x7fffffff,n=(index[id+1]&0x7fffffff)-off;const unsigned char *p=raw+off;
        if(packed){if(!read_bytes(s,length,off,n,scratch))abort();p=scratch;}
        sum+=n;if(n)sum+=p[0]+p[n-1];
    }
    sink=sum;return now()-start;
}
int main(int argc,char **argv){
    if(argc!=6){fprintf(stderr,"usage: %s DATA INDEX BLOCK_BYTES CACHE_BYTES LEVEL\n",argv[0]);return 1;}
    size_t length,indexbytes;unsigned char *raw=file(argv[1],&length);uint32_t *index=(uint32_t *)file(argv[2],&indexbytes);
    if(indexbytes<8||indexbytes%4)return 2;
    size_t records=indexbytes/4-1,maxlen=0;
    if((index[0]&0x7fffffff)!=0 || (index[records]&0x7fffffff)!=length)return 2;
    for(size_t i=0;i<records;i++){size_t off=index[i]&0x7fffffff,end=index[i+1]&0x7fffffff;if(end<off||end>length||end-off>4u*UINT16_MAX)return 2;if((index[i]>>31)&&((end-off)%2))return 2;if(end-off>maxlen)maxlen=end-off;}
    struct store s={0};size_t blocksize=strtoull(argv[3],NULL,10),cachebytes=strtoull(argv[4],NULL,10);int level=atoi(argv[5]);
    double start=now();if(!build(&s,raw,length,blocksize,cachebytes,level))return 3;double build_seconds=now()-start;
    unsigned char *scratch=memory(maxlen>blocksize?maxlen:blocksize);
    for(size_t i=0;i<records;i++){size_t off=index[i]&0x7fffffff,n=(index[i+1]&0x7fffffff)-off;if(!read_bytes(&s,length,off,n,scratch)||memcmp(scratch,raw+off,n))abort();}
    if(read_bytes(&s,length,length,1,scratch)||read_bytes(&s,length,SIZE_MAX,1,scratch))abort();
    size_t corrupted=0;
    for(size_t id=0;id<s.count;id++)if(!s.blocks[id].raw){struct block *b=&s.blocks[id];size_t last=b->offset+b->length-1;clear(&s);s.data[last]^=1;if(block(&s,id))abort();s.data[last]^=1;
        clear(&s);b->length--;if(block(&s,id))abort();b->length++;
        b->decoded--;if(block(&s,id))abort();b->decoded++;
        clear(&s);if(!block(&s,id))abort();corrupted++;break;}
    if(!corrupted)return 4;
    size_t workspace=ZSTD_sizeof_DCtx(s.decoder),allocatedcache=s.slots*s.blocksize+s.slots*sizeof(size_t);
    printf("{\"kind\":\"token_blocks\",\"block_bytes\":%zu,\"cache_bytes\":%zu,\"level\":%d,\"records\":%zu,\"raw_payload_bytes\":%zu,\"encoded_payload_bytes\":%zu,\"block_directory_bytes\":%zu,\"token_index_bytes\":%zu,\"decoder_bytes\":%zu,\"scratch_bytes\":%zu,\"total_layout_bytes\":%zu,\"build_seconds\":%.9f,\"every_token_bytes_verified\":true,\"corruption_and_truncation_rejected\":true}\n",blocksize,allocatedcache,level,records,length,s.size,s.count*sizeof(struct block),indexbytes,workspace,maxlen>blocksize?maxlen:blocksize,s.size+s.count*sizeof(struct block)+indexbytes+workspace+allocatedcache+(maxlen>blocksize?maxlen:blocksize)+sizeof(s),build_seconds);
    fflush(stdout);size_t count=4096;uint32_t *queries=memory(count*4),*first=memory(s.count*4);for(size_t i=0;i<s.count;i++)first[i]=UINT32_MAX;
    for(size_t i=0;i<records;i++){size_t b=(index[i]&0x7fffffff)/s.blocksize;if(b<s.count&&first[b]==UINT32_MAX)first[b]=i;}
    uint64_t seed=261027;
    for(unsigned kind=0;kind<4;kind++){
        size_t conflict=s.slots<s.count?s.slots:0;
        for(size_t i=0;i<count;i++)queries[i]=kind==0?rng(&seed)%records:kind==1?i%records:kind==2?i%(records<32?records:32):first[(i&1)?conflict:0];
        for(size_t i=0;i<count;i++)if(queries[i]==UINT32_MAX)queries[i]=0;
        for(unsigned trial=0;trial<4;trial++){
            double times[2];uint64_t sums[2];size_t hits=0,misses=0;
            for(unsigned order=0;order<2;order++){unsigned mode=order^(trial&1);if(mode)clear(&s);times[mode]=lookup(&s,raw,length,index,queries,count,scratch,mode);sums[mode]=sink;if(mode){hits=s.hits;misses=s.misses;}}
            if(sums[0]!=sums[1])abort();
            printf("{\"kind\":\"token_timing\",\"block_bytes\":%zu,\"cache_budget\":%zu,\"level\":%d,\"input\":%u,\"trial\":%u,\"queries\":%zu,\"raw_seconds\":%.9f,\"packed_seconds\":%.9f,\"cache_hits\":%zu,\"cache_misses\":%zu}\n",blocksize,cachebytes,level,kind,trial,count,times[0],times[1],hits,misses);
        }
    }
    free(first);free(queries);free(scratch);free(index);free(raw);free(s.blocks);free(s.data);free(s.cache);free(s.cached);ZSTD_freeDCtx(s.decoder);return 0;
}
