#![allow(dead_code)]

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const IMAGE: &str = "cratty-test-sshd:3";
const CONTEXT: &str = "tests/docker";

pub const USER: &str = "tester";
pub const PASSWORD: &str = "s3cret";

const READY_TIMEOUT: Duration = Duration::from_secs(60);

pub struct DockerSshd {
    container: String,
    addr: SocketAddr,
    fingerprint: String,
}

impl DockerSshd {
    pub fn start() -> Option<Self> {
        if !docker_available() {
            assert!(
                std::env::var_os("CRATTY_REQUIRE_DOCKER").is_none(),
                "CRATTY_REQUIRE_DOCKER is set, but docker is unavailable"
            );
            return None;
        }

        run(&["build", "-q", "-t", IMAGE, CONTEXT], "building the sshd image");

        let container = run(
            &["run", "-d", "--rm", "-p", "127.0.0.1:0:22", IMAGE],
            "starting the sshd container",
        )
        .trim()
        .to_string();

        let sshd = Self {
            addr: published_port(&container),
            fingerprint: host_key_fingerprint(&container),
            container,
        };
        sshd.wait_until_ready();
        Some(sshd)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut last = String::from("no attempts");

        while Instant::now() < deadline {
            match self.read_banner() {
                Ok(banner) if banner.starts_with("SSH-2.0") => return,
                Ok(banner) => last = format!("got {banner:?} instead of a banner"),
                Err(err) => last = err,
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        panic!(
            "sshd in container {} did not greet within {:?}: {last}\ncontainer log:\n{}",
            self.container,
            READY_TIMEOUT,
            self.logs()
        );
    }

    fn read_banner(&self) -> Result<String, String> {
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))
            .map_err(|err| format!("could not connect: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|err| format!("could not set the read timeout: {err}"))?;

        let mut buf = [0u8; 16];
        let read = stream
            .read(&mut buf)
            .map_err(|err| format!("could not read the banner: {err}"))?;
        Ok(String::from_utf8_lossy(&buf[..read]).to_string())
    }

    pub fn authorize_key(&self, openssh_public_key: &str) {
        let key = openssh_public_key.trim();
        let ssh_dir = format!("/home/{USER}/.ssh");
        let script = format!(
            "set -e; mkdir -p {ssh_dir}; \
             echo '{key}' > {ssh_dir}/authorized_keys; \
             chown -R {USER}:{USER} {ssh_dir}; \
             chmod 700 {ssh_dir}; chmod 600 {ssh_dir}/authorized_keys"
        );
        run(
            &["exec", &self.container, "sh", "-c", &script],
            "writing authorized_keys",
        );
    }

    pub fn logs(&self) -> String {
        let output = Command::new("docker")
            .args(["logs", &self.container])
            .output();
        match output {
            Ok(output) => format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(err) => format!("<could not read the log: {err}>"),
        }
    }
}

impl Drop for DockerSshd {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["kill", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn published_port(container: &str) -> SocketAddr {
    let output = run(&["port", container, "22"], "reading the forwarded port");
    output
        .lines()
        .find_map(|line| line.trim().parse::<SocketAddr>().ok())
        .unwrap_or_else(|| panic!("could not parse the address from `docker port`: {output:?}"))
}

fn host_key_fingerprint(container: &str) -> String {
    let output = run(
        &[
            "exec",
            container,
            "ssh-keygen",
            "-lf",
            "/etc/ssh/ssh_host_ed25519_key.pub",
        ],
        "reading the host key fingerprint",
    );
    output
        .split_whitespace()
        .find(|word| word.starts_with("SHA256:"))
        .unwrap_or_else(|| panic!("could not find the fingerprint in ssh-keygen output: {output:?}"))
        .to_string()
}

fn run(args: &[&str], what: &str) -> String {
    const ATTEMPTS: usize = 5;
    let mut last = String::new();

    for attempt in 1..=ATTEMPTS {
        let output = Command::new("docker")
            .args(args)
            .output()
            .unwrap_or_else(|err| panic!("{what}: could not run docker: {err}"));

        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).to_string();
        }

        last = format!(
            "{what}: docker {args:?} exited with {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        if !is_context_race(&last) {
            panic!("{last}");
        }
        std::thread::sleep(std::time::Duration::from_millis(300 * attempt as u64));
    }

    panic!("{last}\n(repeated {ATTEMPTS} times: docker context file is busy with another process)");
}

fn is_context_race(message: &str) -> bool {
    message.contains("unable to resolve docker endpoint")
        || message.contains("being used by another process")
}
