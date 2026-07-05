#[test]
fn links_are_current() {
    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/README.md");
    let readme = std::fs::read_to_string(PATH).unwrap();
    let sbpf_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let agave_tag = include_str!("../agave_tag.txt").trim();

    let line = readme
        .lines()
        .find(|line| line.starts_with("This is a fork of "))
        .unwrap();

    assert_eq!(
        inline_link_text_and_targets(line),
        vec![
            (
                format!("solana-sbpf {sbpf_tag}"),
                format!("https://github.com/anza-xyz/sbpf/tree/{sbpf_tag}"),
            ),
            (
                format!("Agave {agave_tag}"),
                format!("https://github.com/anza-xyz/agave/tree/{agave_tag}"),
            ),
        ],
    );
}

fn inline_link_text_and_targets(line: &str) -> Vec<(String, String)> {
    let mut text_and_targets = Vec::new();
    let mut rest = line;

    while let Some(anchor_start) = rest.find('[') {
        rest = &rest[anchor_start + 1..];
        let Some(anchor_end) = rest.find(']') else {
            break;
        };
        let text = &rest[..anchor_end];
        rest = &rest[anchor_end + 1..];

        if !rest.starts_with('(') {
            continue;
        }
        rest = &rest[1..];
        let Some(url_end) = rest.find(')') else {
            break;
        };
        let target = &rest[..url_end];
        rest = &rest[url_end + 1..];

        text_and_targets.push((text.to_string(), target.to_string()));
    }

    text_and_targets
}
