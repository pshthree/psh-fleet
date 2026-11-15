use serde::Serialize;

/// Coarse file type from magic bytes. Extensions are never trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Pe,
    Elf,
    MachO,
    Dex,
    Zip,
    Gzip,
    Pdf,
    Ole,
    Lnk,
    Rtf,
    Script,
    Unknown,
}

const EOCD: &[u8] = b"PK\x05\x06";
// The end-of-central-directory record is 22 bytes plus a comment of up to 65535.
const EOCD_SEARCH_WINDOW: usize = 22 + 65_535;

pub fn sniff(data: &[u8]) -> FileType {
    const MACHO: [[u8; 4]; 4] = [
        [0xFE, 0xED, 0xFA, 0xCE],
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCE, 0xFA, 0xED, 0xFE],
        [0xCF, 0xFA, 0xED, 0xFE],
    ];
    if data.starts_with(b"MZ") {
        FileType::Pe
    } else if data.starts_with(b"\x7fELF") {
        FileType::Elf
    } else if data.len() >= 4 && MACHO.iter().any(|m| data.starts_with(m)) {
        FileType::MachO
    } else if data.starts_with(b"dex\n") {
        FileType::Dex
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(EOCD) {
        FileType::Zip
    } else if data.starts_with(b"\x1f\x8b") {
        FileType::Gzip
    } else if data.starts_with(b"%PDF") {
        FileType::Pdf
    } else if data.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        FileType::Ole
    } else if data.starts_with(b"\x4C\x00\x00\x00\x01\x14\x02\x00") {
        FileType::Lnk
    } else if data.starts_with(b"{\\rtf") {
        FileType::Rtf
    } else if data.starts_with(b"#!") {
        FileType::Script
    } else {
        FileType::Unknown
    }
}

/// True when a ZIP central directory may sit at the end of the data, whatever
/// the leading bytes say. Self-extracting archives and ZIPs with junk
/// prepended to dodge scanners both look like this.
pub(crate) fn has_zip_trailer(data: &[u8]) -> bool {
    let start = data.len().saturating_sub(EOCD_SEARCH_WINDOW);
    data[start..].windows(EOCD.len()).any(|w| w == EOCD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common_types() {
        assert_eq!(sniff(b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(sniff(b"\x7fELF\x02"), FileType::Elf);
        assert_eq!(sniff(b"PK\x03\x04rest"), FileType::Zip);
        assert_eq!(sniff(b"\x1f\x8b\x08"), FileType::Gzip);
        assert_eq!(sniff(b"%PDF-1.7"), FileType::Pdf);
        assert_eq!(sniff(b"#!/bin/sh\n"), FileType::Script);
        assert_eq!(sniff(b"dex\n035\0"), FileType::Dex);
        assert_eq!(sniff(b""), FileType::Unknown);
        assert_eq!(sniff(b"hello"), FileType::Unknown);
    }

    #[test]
    fn finds_zip_trailer_behind_other_content() {
        let mut data = b"MZ fake stub ".to_vec();
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 18]);
        assert!(has_zip_trailer(&data));
        assert!(!has_zip_trailer(b"MZ only a stub"));
        assert!(!has_zip_trailer(b""));
    }
}
