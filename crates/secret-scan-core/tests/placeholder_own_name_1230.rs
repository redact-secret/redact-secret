//! `YOUR_<the slot's own name>` placeholders (redact-secret#1230, round-2
//! regression): admitting a name made its slot readable, and a lead word plus
//! the slot's own name words is a documentation placeholder. Real-shaped values
//! are assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{assert_clean, assert_value, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn random(len: usize, seed: usize) -> String {
    let chars: Vec<char> = ALNUM.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 13 + index * index * 3) % chars.len()])
        .collect()
}

#[test]
fn a_lead_word_and_the_slots_own_name_is_a_placeholder_in_every_carrier() {
    for placeholder in [
        "YOUR_HAPIKEY",
        "your-hapikey",
        "Your.Hapikey",
        "YOURHAPIKEY",
        "INSERT_HAPIKEY",
        "enter_your_hapikey",
    ] {
        // `enter_your_hapikey` is two leads: it is read by the existing rule.
        assert_clean(&format!(
            "curl \"https://api.hubspot.example.test/x?hapikey={placeholder}\"\n"
        ));
        assert_clean(&format!(
            "GET /x?count=1&hapikey={placeholder}&b=2 HTTP/1.1\n"
        ));
        assert_clean(&format!("HAPIKEY={placeholder}\n"));
        assert_clean(&format!("HUBSPOT_HAPIKEY=\"{placeholder}\"\n"));
        assert_clean(&format!("{{\"hapikey\":\"{placeholder}\"}}\n"));
    }
}

#[test]
fn the_other_names_admitted_by_the_closeout_fixes_have_the_same_cover() {
    for input in [
        "personalAccessKey: YOUR_PERSONAL_ACCESS_KEY\n",
        "HUBSPOT_PERSONAL_ACCESS_KEY=YOUR_PERSONAL_ACCESS_KEY\n",
        "GET /a HTTP/1.1\nX-JFrog-Art-Api: YOUR_ART_API\n",
        "GET /a HTTP/1.1\nX-JFrog-Art-API: YOUR_JFROG_ART_API\n",
        "GET /a HTTP/1.1\nX-JFrog-Art-Api: YOUR_X_JFROG_ART_API\n",
        "{\"tokenKey\":\"YOUR_TOKENKEY\"}\n",
        "{\"tokenKey\":\"YOUR_TOKEN_KEY\"}\n",
        "{\n  \"api_key\": \"YOUR_API_KEY\",\n  \"encoded\": \"YOUR_ENCODED\"\n}\n",
        "{\"privateKey\":\"YOUR_PRIVATEKEY\"}\n",
        "private_api_key = \"YOUR_PRIVATE_API_KEY\"\n",
        "public_api_key = \"YOUR_PUBLIC_API_KEY\"\n",
        "MONGODB_ATLAS_PUBLIC_API_KEY=YOUR_PUBLIC_API_KEY\n",
        "{\"credentials\": \"YOUR_CREDENTIALS\"}\n",
        "ZENDESK_BASIC_CREDENTIALS=YOUR_BASIC_CREDENTIALS\n",
        "mac_secret_base64: YOUR_MAC_SECRET_BASE64\n",
        "FAL_KEY=YOUR_FAL_KEY\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn real_shaped_values_and_other_words_stay_detected() {
    let secret = random(32, 1);
    // Random material glued to or after the placeholder, the name inside a
    // random value, another name's words, and a lead with nothing.
    for value in [
        format!("YOUR_HAPIKEY{secret}"),
        format!("YOUR_HAPIKEY_{secret}"),
        format!("{secret}YOUR_HAPIKEY"),
        format!("{}hapikey{}", random(10, 2), random(10, 3)),
        "YOUR_OTHER_KEY_NAME".to_owned(),
        "YOUR_HAPIKEYS".to_owned(),
        "YOUR_".to_owned(),
    ] {
        if value.len() < 8 {
            continue;
        }
        let findings = findings_with_parity(&format!("GET /x?hapikey={value} HTTP/1.1\n"));
        assert!(!findings.is_empty(), "{value}");
    }
    assert_value(&format!("GET /x?hapikey={secret} HTTP/1.1\n"), &secret);
    assert_value(&format!("{{\"hapikey\":\"{secret}\"}}\n"), &secret);
    // `my` is not a lead word: `my` plus the name is a weak real value.
    let findings = findings_with_parity("HAPIKEY=my_hapikey\n");
    assert!(!findings.is_empty());
}
