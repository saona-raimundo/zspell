//! Things required to download dictionaries from wooorm's repository
//!
//! This is a work in progress; entire section is largely unfinished
// TODO: should this move to `zspell` under a feature?

#![allow(unused)] // WIP

use std::cmp::{max, min};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use cfg_if::cfg_if;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

// For default use, we get the content listing from Github. For testing,
// we use a dummy server.
cfg_if! {
    if #[cfg(not(test))] {
        const ROOT_URL: &str = "https://api.github.com/repos/wooorm/dictionaries/contents/dictionaries";
        fn get_root_url() -> String {
            ROOT_URL.to_owned()
        }
    } else {
        use lazy_static::lazy_static;
        use httpmock::prelude::*;

        lazy_static!{
            static ref TEST_SERVER: MockServer = MockServer::start();
        }

        fn get_root_url() -> String {
            TEST_SERVER.url("/content/dictionaries")
        }
    }
}

/// A simple struct we can use for download info
/// This may hold URLs, destinations, or content
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct DownloadInfo {
    affix: String,
    dictionary: String,
    license: String,
    lang: String,
}

/// Perform the function that Git does to calculate its hash
///
/// Implementation taken from the git help page, located here
/// <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>
fn calculate_git_hash(bytes: &[u8]) -> [u8; 20] {
    let mut tmp = Vec::from(b"blob ".as_slice());
    tmp.extend_from_slice(bytes.len().to_string().as_bytes());
    tmp.push(b'\0');
    tmp.extend_from_slice(bytes);

    let mut hasher = Sha1::new();
    hasher.update(&tmp);
    let res: [u8; 20] = hasher.finalize().into();
    res
}

fn calculate_git_hash_buf<R: Read>(mut reader: R, len: usize) -> anyhow::Result<[u8; 20]> {
    let mut tmp = String::from("blob ");
    tmp.push_str(&len.to_string());
    tmp.push('\0');

    let mut hasher = Sha1::new();
    hasher.update(tmp.as_bytes());

    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    let res: [u8; 20] = hasher.finalize().into();
    Ok(res)
}

/// Contents of a directory
#[derive(Debug, Deserialize)]
struct Tree(Vec<Listing>);

#[derive(Debug, Deserialize)]
struct Listing {
    name: String,
    path: String,
    size: usize,
    sha: Option<String>,
    url: String,
    html_url: String,
    download_url: Option<String>,
    git_url: String,
    #[serde(rename = "type")]
    ty: String,
}

/// Gather the URLs to download dictionary, affix, and license files from a client
///
/// Only collects the URLs, does not download them. Uses [`get_root_url`]
/// as a base then navigates one layer deeper.
fn retrieve_urls(lang: &str, agent: &ureq::Agent) -> anyhow::Result<DownloadInfo> {
    let tree: Tree = agent
        .get(&get_root_url())
        .call()
        .context("requesting root listing")?
        .into_json()?;

    // Get the URL of the directory to download
    let dir_url = tree
        .0
        .iter()
        .find(|v| v.name == lang && v.ty == "dir")
        .map(|v| &v.url)
        .context("locating selected language")?;

    // Get the listing of that directory
    let dir_tree: Tree = agent
        .get(dir_url)
        .call()
        .context("requesting dictionary listing")?
        .into_json()?;

    let affix = get_dl_url_from_tree(&dir_tree, |s| s.ends_with(".aff"))?;
    let dictionary = get_dl_url_from_tree(&dir_tree, |s| s.ends_with(".dic"))?;
    let license = get_dl_url_from_tree(&dir_tree, |s| s.ends_with("license"))?;

    let res = DownloadInfo {
        affix,
        dictionary,
        license,
        lang: lang.to_string(),
    };

    Ok(res)
}

/// Take in a file tree and locate one where the name matches the specified pattern
fn get_dl_url_from_tree<F: Fn(&str) -> bool>(tree: &Tree, f: F) -> anyhow::Result<String> {
    let ctx_str = "could not locate a necessary file";
    // Collect the SHA sum and download URL of a file
    let tmp = tree
        .0
        .iter()
        .find(|v| f(&v.name))
        .map(|v| (&v.sha, &v.download_url))
        .context(ctx_str)?;

    let mut res = String::from("sha1$");
    res.push_str(tmp.0.as_ref().context(ctx_str)?.as_str());
    res.push('$');
    res.push_str(tmp.1.as_ref().context(ctx_str)?.as_str());

    Ok(res)
}

/// Open an existing file or create a new one, depending on overwrite
/// parameters.
fn open_new_file(path: &Path, overwrite: bool) -> anyhow::Result<File> {
    let fname = path
        .file_name()
        .map(|x| x.to_string_lossy())
        .unwrap_or_default();
    let dir_os = path.with_file_name("");
    let dir = dir_os.to_string_lossy();

    if overwrite {
        // If overwriting is allowed, just create or open the file
        OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)
            .context(format!("unable to open '{fname}' in '{dir}'"))
    } else {
        // Otherwise, use create_new to fail if it exists
        OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .context(format!("file {fname} already exists in '{dir}'"))
    }
}

// Download a single file to the given path, and create a progress bar while
// doing so.
fn download_file_with_bar(
    path: &Path,
    overwrite: bool,
    agent: &ureq::Agent,
    url: &str,
    sha: &[u8],
) -> anyhow::Result<()> {
    const CHUNK_SIZE: usize = 100;

    let mut buffer = open_new_file(path, overwrite)?;
    let resp = agent.get(url).call()?;

    // Estimate content length for our buffer capacity & progress bar
    let expected_len = match resp.header("Content-Length") {
        Some(hdr) => hdr.parse().expect("can't parse number"),
        None => 100,
    };

    let mut buf_len = 0usize;
    let mut buffer: Vec<u8> = Vec::with_capacity(expected_len);
    let mut reader = resp.into_reader().take(10_000_000);

    let pb = ProgressBar::new(expected_len.try_into().unwrap());
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
        .progress_chars("#>-"));
    pb.set_message(format!("Downloading {url}"));

    loop {
        buffer.extend_from_slice(&[0; CHUNK_SIZE]);
        let chunk = &mut buffer.as_mut_slice()[buf_len..buf_len + CHUNK_SIZE];
        let read_bytes = reader.read(chunk).expect("error reading stream");
        buf_len += read_bytes;
        pb.set_length(max(read_bytes, expected_len).try_into().unwrap());
        pb.set_position(buf_len.try_into().unwrap());

        if read_bytes == 0 {
            break;
        }
    }

    buffer.truncate(buf_len);
    let hash = calculate_git_hash(&buffer);

    if hash != sha {
        bail!("error downloading file; checksum failure");
    }

    pb.finish_with_message(format!("Downloaded {} to {}", url, path.to_string_lossy()));

    Ok(())
}

// TODO: make pub
fn download_dict(lang: &str, dest: &Path, overwrite: bool, _manifest: &Path) -> anyhow::Result<()> {
    let client = make_client();
    let urls = retrieve_urls(lang, &client)?;

    let fnames = DownloadInfo {
        affix: format!("{lang}.aff"),
        dictionary: format!("{lang}.dic"),
        license: format!("{lang}.license"),
        lang: String::default(),
    };

    // Want to split "sha$some_sha_hex$some_url" into (some_sha_hex, some_url)
    fn split_url_sha(s: &str) -> (&str, &str) {
        let (sha_pfx, rest) = s.split_once('$').unwrap();
        assert_eq!(sha_pfx, "sha1");

        rest.split_once('$').unwrap()
    }

    let info_aff = split_url_sha(urls.affix.as_str());
    let info_dic = split_url_sha(urls.dictionary.as_str());
    let info_lic = split_url_sha(urls.license.as_str());

    download_file_with_bar(
        &dest.join(fnames.affix),
        overwrite,
        &client,
        info_aff.1,
        hex::decode(info_aff.0.as_bytes())?.as_slice(),
    )?;

    download_file_with_bar(
        &dest.join(fnames.dictionary),
        overwrite,
        &client,
        info_dic.1,
        hex::decode(info_dic.0.as_bytes())?.as_slice(),
    )?;

    download_file_with_bar(
        &dest.join(fnames.license),
        overwrite,
        &client,
        info_lic.1,
        hex::decode(info_lic.0.as_bytes())?.as_slice(),
    )?;

    // Download each with progress bar
    // Hash each file
    // Write download info to toml file

    println!("{urls:?}");

    Ok(())
}

fn make_client() -> ureq::Agent {
    ureq::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(APP_USER_AGENT)
        .build()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use test_mocks::*;

    use super::*;

    #[test]
    fn calculate_git_hash_ok() {
        // Use example from git help page
        assert_eq!(
            calculate_git_hash("what is up, doc?".as_bytes()),
            hex::decode("bd9dbf5aae1a3862dd1526723246b20206e5fc37")
                .unwrap()
                .as_slice()
        )
    }

    #[test]
    fn retreive_urls_ok() {
        let mocks = mock_server_setup();
        let client = make_client();
        dbg!(&mocks);

        let urls = retrieve_urls("de-AT", &client).unwrap();
        // SHA sums joined with files
        let expected = DownloadInfo {
            affix: format!(
                "sha1${}${}",
                CONTENT_AFF_HASH,
                TEST_SERVER
                    .url("/main/dictionaries/de-AT/index.aff")
                    .as_str()
            ),
            dictionary: format!(
                "sha1${}${}",
                CONTENT_DIC_HASH,
                TEST_SERVER
                    .url("/main/dictionaries/de-AT/index.dic")
                    .as_str()
            ),
            license: format!(
                "sha1${}${}",
                CONTENT_LIC_HASH,
                TEST_SERVER.url("/main/dictionaries/de-AT/license").as_str()
            ),
            lang: "de-AT".to_owned(),
        };

        // TODO
        // mocks.dict_listing.assert();
        // mocks.de_at_listing.assert();

        assert_eq!(urls, expected);
    }

    #[test]
    fn download_dict_ok() {
        let mocks = mock_server_setup();
        let dir = tempdir().unwrap();

        let res = download_dict("de-AT", dir.path(), false, &PathBuf::default());

        println!("{res:?}");
        res.unwrap();

        let paths = fs::read_dir(dir.path()).unwrap();

        for path in paths {
            println!("Name: {}", path.unwrap().path().display())
        }

        // TODO: figure out why this isn't being asserted
        // mocks.dict_listing.assert();
        // mocks.de_at_listing.assert();
        // mocks.de_at_aff.assert();
        // mocks.de_at_dic.assert();
        // mocks.de_at_lic.assert();
    }
}

#[cfg(test)]
mod test_mocks {
    use std::fs;

    use httpmock::prelude::*;
    use httpmock::Mock;

    use super::*;

    pub struct TestMocks<'a> {
        pub dict_listing: Mock<'a>,
        pub de_at_listing: Mock<'a>,
        pub de_at_aff: Mock<'a>,
        pub de_at_dic: Mock<'a>,
        pub de_at_lic: Mock<'a>,
    }

    // Content for our mock server
    pub const CONTENT_DIC: &str = "Dictionary Content\n";
    pub const CONTENT_DIC_HASH: &str = "eee2f5c4eddac4175d67c00bc808032b02058b5d";
    pub const CONTENT_AFF: &str = "Affix Content\n";
    pub const CONTENT_AFF_HASH: &str = "a464def0d8bb136f20012d431b60faae2cc915b5";
    pub const CONTENT_LIC: &str = "License Content\n";
    pub const CONTENT_LIC_HASH: &str = "c4d083267263c478591c4856981f32f31690456d";

    macro_rules! make_resp {
        ($path:expr, $ctype:expr, $body:expr) => {
            TEST_SERVER.mock(|when, then| {
                when.method(GET).path($path);
                then.status(200)
                    .header("content-type", "$ctyle; charset=utf-8")
                    .body($body);
            })
        };
    }

    pub fn mock_server_setup<'a>() -> TestMocks<'a> {
        let dict_listing = make_resp!(
            "/contents/dictionaries",
            "application/json",
            fs::read_to_string("tests/files/dict_listing.json")
                .unwrap()
                .replace(r"{{ROOT_URL}}", &TEST_SERVER.base_url())
        );

        let de_at_listing = make_resp!(
            "/contents/dictionaries/de-AT",
            "application/json",
            fs::read_to_string("tests/files/de_at_listing.json")
                .unwrap()
                .replace(r"{{ROOT_URL}}", &TEST_SERVER.base_url())
        );

        let de_at_aff = make_resp!(
            "/main/dictionaries/de-AT/index.aff",
            "text/plain",
            CONTENT_AFF
        );
        let de_at_dic = make_resp!(
            "/main/dictionaries/de-AT/index.dic",
            "text/plain",
            CONTENT_DIC
        );
        let de_at_lic = make_resp!(
            "/main/dictionaries/de-AT/license",
            "text/plain",
            CONTENT_LIC
        );

        TestMocks {
            dict_listing,
            de_at_listing,
            de_at_aff,
            de_at_dic,
            de_at_lic,
        }
    }
}
