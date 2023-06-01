use std::collections::HashMap;
use std::iter::repeat_with;

use compact_str::CompactString;

use super::SmallBytes;
use crate::cgi;
use crate::protocol as fcgi;


pub(super) const BYTES: &[u8] = b"\x1f\x9a\xdaM\xeb\x82U\xb8\xfe\xf4\xb0\xc7\x80\x95\xc6\
    \xdf\xa3\xd3O,\xae\xa3\xa8x\x18@\x9a\xf7\x0f\xd6\x18\xbdv\x90\x80I\xa1\x99\xf8\xec";

pub(super) const PARAMS: &[(&[u8], &[u8])] = &[
    (b"HTTP_DATE", b"Sun, 07 May 2023 19:42:27 GMT"),
    (b"GATEWAY_INTERFACE", b"CGI/1.1"),
    (b"CONTENT_LENGTH", b"67828"),
    (b"REQUEST_METHOD", b"HEAD"),
    (b"HTTP_AuthORIZAtIon", b"Bearer FAKE-xi/atccvRF7tN7p8J4Vw+KJ3AhikzBNhIBo0zQc7be5E"),
    (b"HTTP_x_unknown_test", b"Z+5ED\\SHGMN76&T}+fc%DE40@.jG"),
    (b"HTTP_X_NOT_UTF8", BYTES),
    (b"HTTP_X_FORWARDED_PROTO", b"https"),
    (b"CONTENT_TYPE", b"text/plain"),
    (b"HTTP_x_INVAL\xFF\xFE_head", b"az%baqw&W2bAbwA"),
];

pub(super) fn params_map() -> HashMap<cgi::OwnedVarName, SmallBytes> {
    PARAMS
        .iter()
        .map(|&(n, v)| {
            let name = CompactString::from_utf8_lossy(n);
            (cgi::OwnedVarName::from_compact(name), SmallBytes::from_slice(v))
        })
        .collect()
}


pub(super) fn add_unk(buf: &mut Vec<u8>, req_id: u16, rtype: u8) {
    let rand_len = fastrand::u16(10..512);
    let mut head = [0; 8];
    head[0] = 1;
    head[1] = rtype;
    head[2..4].copy_from_slice(&req_id.to_be_bytes());
    head[4..6].copy_from_slice(&rand_len.to_be_bytes());
    buf.extend(head);
    buf.extend(repeat_with(|| fastrand::u8(..)).take(rand_len.into()));
}

/// Uses [`fcgi::Role::Responder`] and full [`fcgi::RequestFlags`].
pub(super) fn add_begin(buf: &mut Vec<u8>, req_id: u16) {
    buf.extend(fcgi::body::BeginRequest {
        role: fcgi::Role::Responder, flags: fcgi::RequestFlags::all(),
    }.to_record(req_id));
}

pub(super) fn add_abort(buf: &mut Vec<u8>, req_id: u16) {
    buf.extend(fcgi::RecordHeader::new(fcgi::RecordType::AbortRequest, req_id).to_bytes());
}

pub(super) fn add_get_vals(buf: &mut Vec<u8>, req_id: u16) {
    const VALS: &[u8] = b"\x0e\x00FCGI_MAX_CONNS\x0d\x00FCGI_MAX_REQS\x0f\x00FCGI_MPXS_CONNS";
    buf.extend(fcgi::RecordHeader {
        version: fcgi::Version::V1, rtype: fcgi::RecordType::GetValues,
        request_id: req_id, content_length: VALS.len() as u16, padding_length: 0,
    }.to_bytes());
    buf.extend(VALS);
}

pub(super) const VALS_RESULT1: &[u8] = b"\x01\x0a\0\0\x00\x33\x05\0\x0e\x01FCGI_MAX_CONNS1\
    \x0d\x01FCGI_MAX_REQS1\x0f\x01FCGI_MPXS_CONNS0\0\0\0\0\0";

pub(super) fn add_params<'a, I>(buf: &mut Vec<u8>, req_id: u16, params: I, lens: &[u16])
where
    I: Iterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut recs = lens.iter().copied();
    let mut rem = recs.next().unwrap_or(u16::MAX);
    let mut head = fcgi::RecordHeader {
        version: fcgi::Version::V1, rtype: fcgi::RecordType::Params,
        request_id: req_id, content_length: rem, padding_length: 0,
    };

    let mut head_start = buf.len();
    buf.extend(head.to_bytes());

    for nv in params {
        let mut written = fcgi::nv::write(nv, &mut *buf).unwrap();
        while let Some(new_written) = written.checked_sub(rem.into()) {
            // Splice a new header after end of previous' payload
            written = new_written;
            rem = recs.next().unwrap_or(u16::MAX);
            head.content_length = rem;

            head_start = buf.len() - written;
            buf.splice(head_start..head_start, head.to_bytes());
        }
        rem -= written as u16;
    }

    // Fix up the payload length of the last header
    head.content_length -= rem;
    assert_eq!(head_start + 8, buf.len() - usize::from(head.content_length));
    buf[head_start..(head_start + 8)].copy_from_slice(&head.to_bytes());

    // Add the stream end header (if necessary)
    if head.content_length != 0 {
        head.content_length = 0;
        buf.extend(head.to_bytes());
    }
}

pub(super) fn add_input(buf: &mut Vec<u8>, req_id: u16, stream: fcgi::RecordType, lens: &[u16]) {
    assert!(stream.is_input_stream());
    let mut head = fcgi::RecordHeader::new(stream, req_id);
    for &amt in lens {
        head.content_length = amt;
        buf.extend(head.to_bytes());
        buf.extend(repeat_with(|| fastrand::u8(..)).take(amt.into()));
    }

    // Add the stream end header
    head.content_length = 0;
    buf.extend(head.to_bytes());
}

pub(super) fn randomize_padding(buf: &mut Vec<u8>) {
    let mut head_start = 0;
    while let Some(head) = buf.get_mut(head_start..(head_start + 8)) {
        let payload = u16::from_be_bytes([head[4], head[5]]);
        let old_pad = head[6];
        let new_pad = fastrand::u8(..);
        head[6] = new_pad;

        head_start += 8 + usize::from(payload);
        buf.splice(
            head_start..(head_start + usize::from(old_pad)),
            repeat_with(|| fastrand::u8(..)).take(new_pad.into()),
        );
        head_start += usize::from(new_pad);
    }
}
