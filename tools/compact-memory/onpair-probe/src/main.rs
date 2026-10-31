// SPDX-License-Identifier: MIT
// Standalone research executable; never linked into the scanner.
use std::{env, fs, hint::black_box, mem::{size_of,MaybeUninit}, time::Instant};
use onpair::{Column, CompactDictionary, Dictionary, Config, DECODE_PADDING, MaxDictBits, OwnedDictionaryStorage, Threshold, try_decode_into};
fn rng(s: &mut u64)->u64 {*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;*s}
fn row_codes(col: &Column<u32>, i: usize) -> &[u16] {
    &col.codes[(col.row_offsets[i]&0x7fffffff) as usize..(col.row_offsets[i+1]&0x7fffffff) as usize]
}
fn main() {
    let args:Vec<_>=env::args().collect(); assert_eq!(args.len(),4,"DATA INDEX DICT_BITS");
    let data=fs::read(&args[1]).unwrap(); let raw_index=fs::read(&args[2]).unwrap(); assert_eq!(raw_index.len()%4,0);
    let encoded:Vec<u32>=raw_index.chunks_exact(4).map(|x|u32::from_le_bytes(x.try_into().unwrap())).collect();
    let offsets:Vec<u32>=encoded.iter().map(|v|v&0x7fffffff).collect(); let rows=offsets.len()-1;
    assert_eq!(offsets[0],0);assert_eq!(offsets[rows] as usize,data.len());
    let mut wide=vec![0u8;rows.div_ceil(8)];let mut maxlen=0;let mut longest=0;
    for i in 0..rows {assert!(offsets[i]<=offsets[i+1]); let n=(offsets[i+1]-offsets[i]) as usize;
        if n>maxlen {maxlen=n;longest=i;} if encoded[i]>>31 !=0 {assert_eq!(n%2,0);wide[i/8]|=1<<(i%8);}}
    let bits:u8=args[3].parse().unwrap();
    let cfg=Config{max_dict_bits:MaxDictBits::new(bits).unwrap(),threshold:Threshold::new(0.15).unwrap(),seed:Some(42)};
    let start=Instant::now(); let mut col=Column::<u32>::compress(&data,&offsets,cfg).unwrap(); let build=start.elapsed().as_secs_f64();
    col.codes.shrink_to_fit();col.row_offsets.shrink_to_fit();
    let (dict, codes, row_offsets)=col.into_raw();let (mut db,mut di)=dict.into_raw();db.shrink_to_fit();di.shrink_to_fit();
    let dict_bytes=db.len()+di.len()*4;let dict_capacity=db.capacity()+di.capacity()*4;
    let dict=CompactDictionary::validate(OwnedDictionaryStorage::new(db,di)).unwrap();
    let mut col=Column{dict,codes,row_offsets};
    let flagged=env::var_os("TOKEN_INDEX_FLAGS").is_some();
    assert!(col.codes.len()<=data.len() && data.len()<1usize<<31);
    if flagged {
        for i in 0..rows {col.row_offsets[i]|=encoded[i]&0x80000000;}
        wide=Vec::new();
    }
    let dictionary=col.dict.as_view();
    let mut scratch=vec![MaybeUninit::<u8>::uninit();maxlen+DECODE_PADDING];
    for i in 0..rows {
        let n=try_decode_into(row_codes(&col,i),dictionary,&mut scratch).unwrap();
        // Safe decoder initialized exactly its returned prefix.
        let out=unsafe{std::slice::from_raw_parts(scratch.as_ptr().cast::<u8>(),n)};
        assert_eq!(out,&data[offsets[i] as usize..offsets[i+1] as usize]);
        let width=if flagged {(col.row_offsets[i]>>31) as u8} else {(wide[i/8]>>(i%8))&1};
        assert_eq!(width,(encoded[i]>>31) as u8);
    }
    let too_short=try_decode_into(row_codes(&col,longest),dictionary,&mut []).is_err();assert!(too_short);
    let malformed=CompactDictionary::validate_safety(OwnedDictionaryStorage::new(vec![0;32],vec![0,17])).is_err();assert!(malformed);
    let payload=col.codes.len()*2;let index=col.row_offsets.len()*4;
    let total=payload+index+dict_bytes+wide.len()+scratch.len()+size_of::<Column<u32>>()+(if flagged {1}else{2})*size_of::<Vec<u8>>();
    let allocated=col.codes.capacity()*2+col.row_offsets.capacity()*4+dict_capacity+wide.capacity()+scratch.capacity()+size_of::<Column<u32>>()+(if flagged {1}else{2})*size_of::<Vec<u8>>();
    println!("{{\"kind\":\"onpair\",\"dict_bits\":{bits},\"flagged_offsets\":{flagged},\"rows\":{rows},\"raw_payload_bytes\":{},\"codes\":{},\"code_bytes\":{payload},\"index_bytes\":{index},\"dictionary_bytes\":{dict_bytes},\"width_bitmap_bytes\":{},\"scratch_bytes\":{},\"total_layout_bytes\":{total},\"allocated_layout_bytes\":{allocated},\"build_seconds\":{build},\"every_token_verified\":true,\"too_small_output_rejected\":{too_short},\"malformed_dictionary_rejected\":{malformed}}}",data.len(),col.codes.len(),wide.len(),scratch.len());
    let mut seed=261027;let count=262144;
    for mode in 0..5 {
        let queries:Vec<usize>=(0..count).map(|i|match mode {0=>(rng(&mut seed) as usize)%rows,1=>i%rows,2=>i%32,3=>longest,_=>if i%2==0 {0}else{rows-1}}).collect();
        for trial in 0..5 {
            let mut times=[0.;2];let mut checksums=[0u64;2];
            for order in 0..2 {let packed=order^(trial&1);let start=Instant::now();let mut sum=0u64;
                for &i in &queries {
                    let out=if packed==1 {let n=try_decode_into(row_codes(&col,i),dictionary,&mut scratch).unwrap(); unsafe{std::slice::from_raw_parts(scratch.as_ptr().cast::<u8>(),n)}} else {&data[offsets[i] as usize..offsets[i+1] as usize]};
                    let out=black_box(out);sum+=out.len() as u64;if !out.is_empty(){sum+=out[0] as u64+out[out.len()-1] as u64;}
                }
                checksums[packed]=black_box(sum);times[packed]=start.elapsed().as_secs_f64();
            }
            assert_eq!(checksums[0],checksums[1]);
            println!("{{\"kind\":\"onpair_timing\",\"dict_bits\":{bits},\"mode\":{mode},\"trial\":{trial},\"queries\":{count},\"raw_seconds\":{},\"packed_seconds\":{},\"checksum\":{}}}",times[0],times[1],checksums[0]);
        }
    }
}
