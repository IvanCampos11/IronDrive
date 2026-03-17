/// Detect MIME type from a file extension. Returns `None` if the type
/// cannot be determined. Uses the `mime_guess` crate internally.
///
/// Since IronDrive encrypts file contents, magic-byte detection won't work —
/// encrypted bytes have no valid magic headers. We rely solely on extensions.
#[inline]
pub fn mime_from_filename(filename: &str) -> Option<String> {
    mime_guess::from_path(filename)
        .first()
        .map(|mime| mime.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Common types ──────────────────────────────────────────────────

    #[test]
    fn text_plain() {
        assert_eq!(mime_from_filename("file.txt"), Some("text/plain".into()));
    }

    #[test]
    fn application_pdf() {
        assert_eq!(
            mime_from_filename("file.pdf"),
            Some("application/pdf".into())
        );
    }

    #[test]
    fn image_jpeg() {
        assert_eq!(mime_from_filename("photo.jpg"), Some("image/jpeg".into()));
    }

    #[test]
    fn image_png() {
        assert_eq!(mime_from_filename("image.png"), Some("image/png".into()));
    }

    #[test]
    fn text_html() {
        assert_eq!(mime_from_filename("index.html"), Some("text/html".into()));
    }

    #[test]
    fn application_json() {
        assert_eq!(
            mime_from_filename("data.json"),
            Some("application/json".into())
        );
    }

    #[test]
    fn video_mp4() {
        assert_eq!(mime_from_filename("video.mp4"), Some("video/mp4".into()));
    }

    #[test]
    fn application_zip() {
        assert_eq!(
            mime_from_filename("archive.zip"),
            Some("application/zip".into())
        );
    }

    #[test]
    fn image_svg() {
        assert_eq!(mime_from_filename("icon.svg"), Some("image/svg+xml".into()));
    }

    #[test]
    fn text_xml() {
        // mime_guess returns "text/xml" for .xml (not "application/xml")
        assert_eq!(mime_from_filename("config.xml"), Some("text/xml".into()));
    }

    #[test]
    fn text_css() {
        assert_eq!(mime_from_filename("style.css"), Some("text/css".into()));
    }

    #[test]
    fn application_javascript() {
        // mime_guess returns "application/javascript" for .js
        let result = mime_from_filename("app.js");
        assert!(result.is_some());
        let mime = result.unwrap();
        assert!(
            mime.contains("javascript"),
            "expected javascript MIME, got: {mime}"
        );
    }

    // ─── Case insensitivity ────────────────────────────────────────────

    #[test]
    fn uppercase_extension() {
        assert_eq!(mime_from_filename("photo.JPEG"), Some("image/jpeg".into()));
    }

    #[test]
    fn mixed_case_extension() {
        assert_eq!(mime_from_filename("photo.JpG"), Some("image/jpeg".into()));
    }

    #[test]
    fn uppercase_png() {
        assert_eq!(mime_from_filename("IMAGE.PNG"), Some("image/png".into()));
    }

    // ─── Multi-extension filenames ─────────────────────────────────────

    #[test]
    fn tar_gz_uses_last_extension() {
        // mime_guess uses the final extension: ".gz" → application/gzip
        let result = mime_from_filename("archive.tar.gz");
        assert!(result.is_some());
        let mime = result.unwrap();
        assert!(
            mime.contains("gzip") || mime.contains("gz"),
            "expected gzip MIME for .tar.gz, got: {mime}"
        );
    }

    #[test]
    fn backup_with_multiple_dots() {
        // "report.2024.01.pdf" — last extension is ".pdf"
        assert_eq!(
            mime_from_filename("report.2024.01.pdf"),
            Some("application/pdf".into())
        );
    }

    // ─── No match / unknown ────────────────────────────────────────────

    #[test]
    fn unknown_extension() {
        assert_eq!(mime_from_filename("file.xyz123"), None);
    }

    #[test]
    fn no_extension() {
        assert_eq!(mime_from_filename("README"), None);
    }

    #[test]
    fn empty_string() {
        assert_eq!(mime_from_filename(""), None);
    }

    #[test]
    fn dotfile_unknown_extension() {
        // `.gitignore` — mime_guess treats "gitignore" as the extension,
        // which is not a recognized MIME type.
        assert_eq!(mime_from_filename(".gitignore"), None);
    }

    #[test]
    fn dotfile_known_extension() {
        // `.html` — mime_guess treats the entire filename as the stem when
        // it starts with a dot and has no other dot, so there is no
        // extension to match. Returns None.
        assert_eq!(mime_from_filename(".html"), None);
    }

    // ─── Paths (not just bare filenames) ───────────────────────────────

    #[test]
    fn full_path_posix() {
        assert_eq!(
            mime_from_filename("docs/report.pdf"),
            Some("application/pdf".into())
        );
    }

    #[test]
    fn deeply_nested_path() {
        assert_eq!(
            mime_from_filename("a/b/c/d/photo.jpg"),
            Some("image/jpeg".into())
        );
    }

    #[test]
    fn path_with_spaces() {
        assert_eq!(
            mime_from_filename("My Documents/my file.txt"),
            Some("text/plain".into())
        );
    }

    #[test]
    fn path_with_unicode() {
        assert_eq!(
            mime_from_filename("文件/图片.png"),
            Some("image/png".into())
        );
    }

    // ─── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn just_a_dot() {
        assert_eq!(mime_from_filename("."), None);
    }

    #[test]
    fn double_dot() {
        assert_eq!(mime_from_filename(".."), None);
    }

    #[test]
    fn trailing_dot() {
        // "file." — empty extension, no match
        assert_eq!(mime_from_filename("file."), None);
    }

    #[test]
    fn filename_is_only_extension() {
        // ".txt" — mime_guess treats this as a dotfile with stem "txt" and
        // no extension, so it returns None.
        assert_eq!(mime_from_filename(".txt"), None);
    }
}
