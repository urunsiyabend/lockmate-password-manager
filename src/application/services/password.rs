use rand::{Rng, distributions::Uniform, seq::SliceRandom, thread_rng};
use serde::Serialize;

const DEFAULT_WORD_LIST: &[&str] = &[
    "anchor",
    "autumn",
    "binary",
    "blizzard",
    "breeze",
    "cascade",
    "celestial",
    "citadel",
    "cobalt",
    "comet",
    "compass",
    "crimson",
    "crystal",
    "ember",
    "emerald",
    "fable",
    "falcon",
    "fathom",
    "festival",
    "frost",
    "galaxy",
    "glacier",
    "harbor",
    "harmony",
    "horizon",
    "inkwell",
    "lantern",
    "lattice",
    "lunar",
    "meadow",
    "melody",
    "mirage",
    "nebula",
    "nectar",
    "nickel",
    "nomad",
    "onyx",
    "opal",
    "orchid",
    "origin",
    "paladin",
    "panorama",
    "pebble",
    "phoenix",
    "pinnacle",
    "quartz",
    "quill",
    "raven",
    "resonant",
    "ridge",
    "saffron",
    "sage",
    "scarlet",
    "serene",
    "shadow",
    "sierra",
    "solstice",
    "sparrow",
    "stellar",
    "summit",
    "thistle",
    "tidal",
    "topaz",
    "torrent",
    "traverse",
    "twilight",
    "valiant",
    "velvet",
    "verve",
    "vertex",
    "voyage",
    "walnut",
    "whisper",
    "willow",
    "zephyr",
];

#[derive(Debug, Clone)]
pub struct PassphraseOptions<'a> {
    pub word_count: usize,
    pub separator: &'a str,
    pub capitalize: bool,
    pub include_number: bool,
    pub number_digits: usize,
    pub include_symbol: bool,
    pub symbol_set: &'a str,
}

impl<'a> Default for PassphraseOptions<'a> {
    fn default() -> Self {
        Self {
            word_count: 4,
            separator: "-",
            capitalize: true,
            include_number: true,
            number_digits: 2,
            include_symbol: false,
            symbol_set: "!@#$%^&*",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthScore {
    VeryWeak,
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordComplexity {
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_numbers: bool,
    pub has_symbols: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordStrengthReport {
    pub length: usize,
    pub entropy_bits: f64,
    pub charset_size: usize,
    pub crack_time_seconds: f64,
    pub score: StrengthScore,
    pub complexity: PasswordComplexity,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedPassword {
    pub password: String,
    pub strength: PasswordStrengthReport,
}

pub fn generate_passphrase(options: PassphraseOptions<'_>) -> GeneratedPassword {
    let mut rng = thread_rng();
    let word_count = options.word_count.max(1).min(16);
    let number_digits = options.number_digits.clamp(1, 8);
    let mut words = Vec::with_capacity(word_count);

    for _ in 0..word_count {
        let word = DEFAULT_WORD_LIST.choose(&mut rng).unwrap_or(&"lockmate");
        if options.capitalize {
            let mut chars = word.chars();
            let capitalized = match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            };
            words.push(capitalized);
        } else {
            words.push((*word).to_string());
        }
    }

    let mut passphrase = words.join(options.separator);

    if options.include_number {
        let digit_dist = Uniform::new_inclusive(0, 9);
        let digits: String = (0..number_digits)
            .map(|_| rng.sample(digit_dist).to_string())
            .collect();
        passphrase.push_str(&digits);
    }

    if options.include_symbol {
        let symbol_candidates: Vec<char> = options.symbol_set.chars().collect();
        if let Some(symbol) = symbol_candidates.choose(&mut rng) {
            passphrase.push(*symbol);
        }
    }

    let strength = evaluate_strength(&passphrase);

    GeneratedPassword {
        password: passphrase,
        strength,
    }
}

pub fn evaluate_strength(password: &str) -> PasswordStrengthReport {
    let length = password.chars().count();
    if length == 0 {
        return PasswordStrengthReport {
            length: 0,
            entropy_bits: 0.0,
            charset_size: 0,
            crack_time_seconds: 0.0,
            score: StrengthScore::VeryWeak,
            complexity: PasswordComplexity {
                has_lowercase: false,
                has_uppercase: false,
                has_numbers: false,
                has_symbols: false,
            },
            suggestions: vec!["Add characters to increase entropy.".to_string()],
        };
    }

    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_numbers = false;
    let mut has_symbols = false;

    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            has_lowercase = true;
        } else if ch.is_ascii_uppercase() {
            has_uppercase = true;
        } else if ch.is_ascii_digit() {
            has_numbers = true;
        } else {
            has_symbols = true;
        }
    }

    let mut charset_size = 0;
    if has_lowercase {
        charset_size += 26;
    }
    if has_uppercase {
        charset_size += 26;
    }
    if has_numbers {
        charset_size += 10;
    }
    if has_symbols {
        charset_size += 33;
    }

    if charset_size == 0 {
        charset_size = password
            .chars()
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1);
    }

    let entropy_bits = (charset_size as f64).log2() * length as f64;
    let guesses_per_second = 1e9_f64;
    let crack_time_seconds = if entropy_bits <= 0.0 {
        0.0
    } else {
        2_f64.powf(entropy_bits) / guesses_per_second
    };

    let score = if entropy_bits < 28.0 {
        StrengthScore::VeryWeak
    } else if entropy_bits < 36.0 {
        StrengthScore::Weak
    } else if entropy_bits < 60.0 {
        StrengthScore::Moderate
    } else if entropy_bits < 100.0 {
        StrengthScore::Strong
    } else {
        StrengthScore::VeryStrong
    };

    let mut suggestions = Vec::new();
    if length < 12 {
        suggestions.push("Use at least 12 characters for better resilience.".to_string());
    }
    if !has_lowercase || !has_uppercase || !has_numbers || !has_symbols {
        suggestions.push("Mix lower, upper, numbers, and symbols to grow the entropy.".to_string());
    }

    PasswordStrengthReport {
        length,
        entropy_bits,
        charset_size,
        crack_time_seconds,
        score,
        complexity: PasswordComplexity {
            has_lowercase,
            has_uppercase,
            has_numbers,
            has_symbols,
        },
        suggestions,
    }
}
