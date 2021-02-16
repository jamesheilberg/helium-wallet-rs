use crate::result::Result;
use regex::Regex;

static WORDS_ENGLISH: &str = include_str!("wordlists/english.txt");

pub enum Language {
    English,
}

impl Language {
    pub fn find_word(&self, user_word: &str) -> Option<usize> {
        match self {
            Language::English => Self::find_english_word(user_word),
        }
    }

    fn find_english_word(user_word: &str) -> Option<usize> {
        // BIP39: the wordlist is created in such a way that it's
        //        enough to type the first four letters to
        //        unambiguously identify the word
        const MIN_CMP_LEN: usize = 4;
        let user_word = user_word.to_ascii_lowercase();
        for (idx, list_word) in WORDS_ENGLISH.lines().enumerate() {
            if user_word.len() >= MIN_CMP_LEN
                && list_word.len() >= MIN_CMP_LEN
                && user_word[..MIN_CMP_LEN] == list_word[..MIN_CMP_LEN]
            {
                return Some(idx);
            }
            if user_word == list_word {
                return Some(idx);
            }
        }
        None
    }
}

/// Converts a 12 word mnemonic to a entropy that can be used to
/// generate a keypair
pub fn mnemonic_to_entropy(words: Vec<String>) -> Result<[u8; 32]> {
    if words.len() != 12 {
        return Err("Invalid number of seed words".into());
    }

    let language = Language::English;

    let bits = words
        .iter()
        .map(|w| {
            language
                .find_word(w)
                .ok_or_else(|| format!("Seed word {} not found in wordlist", w).into())
                .map(|idx| format!("{:011b}", idx))
        })
        .collect::<Result<String>>()?;

    let divider_index: usize = ((bits.len() as f64 / 33.0) * 32.0).floor() as usize;
    let (entropy_bits, checksum_bits) = bits.split_at(divider_index);
    // The mobile wallet does not calculate the checksum bits right so
    // they always and up being all 0
    if checksum_bits != "0000" {
        return Err("invalid checksum".into());
    }

    lazy_static! {
        static ref RE_BYTES: Regex = Regex::new("(.{1,8})").unwrap();
    }

    let mut entropy_base = [0u8; 16];
    for (idx, matched) in RE_BYTES.find_iter(&entropy_bits).enumerate() {
        entropy_base[idx] = binary_to_bytes(matched.as_str()) as u8;
    }

    let mut entropy_bytes = [0u8; 32];
    entropy_bytes[..16].copy_from_slice(&entropy_base);
    entropy_bytes[16..].copy_from_slice(&entropy_base);

    Ok(entropy_bytes)
}

/// Converts a binary string into an integer
fn binary_to_bytes(bin: &str) -> usize {
    usize::from_str_radix(bin, 2).unwrap() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs58;

    #[test]
    fn decode_full_words() {
        // The words and entryopy here were generated from the JS mobile-wallet implementation
        let words = "catch poet clog intact scare jacket throw palm illegal buyer allow figure";
        let expected_entropy = bs58::decode("3RrA1FDa6mdw5JwKbUxEbZbMcJgSyWjhNwxsbX5pSos8")
            .into_vec()
            .expect("decoded entropy");

        let word_list = words.split_whitespace().map(|w| w.to_string()).collect();
        let entropy = mnemonic_to_entropy(word_list).expect("entropy");
        assert_eq!(expected_entropy, entropy);
    }

    #[test]
    fn decode_partial_words() {
        // The words and entryopy here were generated from the JS mobile-wallet implementation
        let words = "catc poet clog inta scar jack thro palm ille buye allo figu";
        let expected_entropy = bs58::decode("3RrA1FDa6mdw5JwKbUxEbZbMcJgSyWjhNwxsbX5pSos8")
            .into_vec()
            .expect("decoded entropy");

        let word_list = words.split_whitespace().map(|w| w.to_string()).collect();
        let entropy = mnemonic_to_entropy(word_list).expect("entropy");
        assert_eq!(expected_entropy, entropy);
    }

    #[test]
    fn decode_three_letter_and_truncated() {
        //           pond heart cage off just payment disorder picture wine gesture draw slot
        let words = "pond heart cage off just paymen  diso     picture wine gestu   draw slot";
        let expected_entropy = bs58::decode("CJ2e4jqyn6AYk6fvgPkqiDmE9JMh8SivLnp3GY2DKTbT")
            .into_vec()
            .expect("decoded entropy");

        let word_list = words.split_whitespace().map(|w| w.to_string()).collect();
        let entropy = mnemonic_to_entropy(word_list).expect("entropy");
        println!("{:02x?}", entropy);
        assert_eq!(expected_entropy, entropy);
    }
}
