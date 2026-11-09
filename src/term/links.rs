pub fn is_openable(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    rest.is_some_and(|rest| !rest.is_empty())
}

pub fn url_at(cells: &[char], column: usize) -> Option<String> {
    if column >= cells.len() {
        return None;
    }
    let text: String = cells.iter().collect();
    let offsets: Vec<usize> = text.char_indices().map(|(offset, _)| offset).collect();
    let lower = text.to_ascii_lowercase();

    let mut from = 0;
    while let Some(found) = find_scheme(&lower[from..]) {
        let start = from + found;
        let start_column = offsets.iter().position(|&offset| offset == start)?;

        let mut end_column = start_column;
        while end_column < cells.len() && is_url_char(cells[end_column]) {
            end_column += 1;
        }
        while end_column > start_column {
            let last = cells[end_column - 1];
            let keep_paren = last == ')' && cells[start_column..end_column - 1].contains(&'(');
            if ".,;:!?'\"]}".contains(last) || (last == ')' && !keep_paren) {
                end_column -= 1;
            } else {
                break;
            }
        }

        if (start_column..end_column).contains(&column) {
            let url: String = cells[start_column..end_column].iter().collect();
            return is_openable(&url).then_some(url);
        }
        from = offsets
            .get(end_column.max(start_column + 1))
            .copied()
            .unwrap_or(text.len());
        if from >= text.len() {
            break;
        }
    }
    None
}

fn find_scheme(lower: &str) -> Option<usize> {
    match (lower.find("https://"), lower.find("http://")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn is_url_char(ch: char) -> bool {
    !ch.is_whitespace() && !ch.is_control() && !"<>\"`".contains(ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: &str, column: usize) -> Option<String> {
        let cells: Vec<char> = line.chars().collect();
        url_at(&cells, column)
    }

    #[test]
    fn url_is_found_under_cursor() {
        let line = "see https://example.com/path?q=1 now";
        assert_eq!(at(line, 4).as_deref(), Some("https://example.com/path?q=1"));
        assert_eq!(
            at(line, 20).as_deref(),
            Some("https://example.com/path?q=1")
        );
        assert_eq!(at(line, 2), None);
        assert_eq!(at(line, 34), None);
    }

    #[test]
    fn trailing_punctuation_is_trimmed() {
        assert_eq!(
            at("see https://x.org.", 6).as_deref(),
            Some("https://x.org")
        );
        assert_eq!(at("(https://x.org)", 3).as_deref(), Some("https://x.org"));
        assert_eq!(
            at("https://en.wikipedia.org/wiki/Rust_(language)", 3).as_deref(),
            Some("https://en.wikipedia.org/wiki/Rust_(language)")
        );
    }

    #[test]
    fn several_urls_in_a_line() {
        let line = "http://a.org and https://b.org";
        assert_eq!(at(line, 2).as_deref(), Some("http://a.org"));
        assert_eq!(at(line, 18).as_deref(), Some("https://b.org"));
    }

    #[test]
    fn http_only() {
        assert!(is_openable("https://x.org"));
        assert!(is_openable("HTTP://x.org"));
        assert!(!is_openable("file:///etc/passwd"));
        assert!(!is_openable("javascript:alert(1)"));
        assert!(!is_openable("ms-settings:"));
        assert!(!is_openable("https://"));
    }
}
