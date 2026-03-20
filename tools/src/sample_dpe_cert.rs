// Licensed under the Apache-2.0 license

use caliptra_dpe::{tci::TciMeasurement, DpeFlags};
use caliptra_dpe_platform::default::DefaultPlatformProfile;
use caliptra_dpe_crypto::CryptoSuite;
use caliptra_dpe_platform::Platform;
use clap::{Parser, ValueEnum};
use profile::*;
use {
    caliptra_dpe::commands::{self, CertifyKeyFlags, DeriveContextCmd, DeriveContextFlags},
    caliptra_dpe::context::ContextHandle,
    caliptra_dpe::dpe_instance::DpeEnv,
    caliptra_dpe::response::Response,
    caliptra_dpe::{support::Support, DpeInstance},
    caliptra_dpe_platform::default::DefaultPlatform,
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    zerocopy::IntoBytes,
};

#[cfg(feature = "p256")]
mod profile {
    use super::*;
    pub use caliptra_dpe::commands::CertifyKeyP256Cmd as CertifyKeyCmd;
    pub const DPE_PROFILE: caliptra_dpe::DpeProfile = caliptra_dpe::DpeProfile::P256Sha256;
    pub const PLATFORM_PROFILE: DefaultPlatformProfile = DefaultPlatformProfile::P256;
    pub fn new_crypto() -> caliptra_dpe_crypto::RustCryptoImpl {
        caliptra_dpe_crypto::RustCryptoImpl::new_ecc256()
    }
}

#[cfg(feature = "p384")]
mod profile {
    use super::*;
    pub use caliptra_dpe::commands::CertifyKeyP384Cmd as CertifyKeyCmd;
    pub const DPE_PROFILE: caliptra_dpe::DpeProfile = caliptra_dpe::DpeProfile::P384Sha384;
    pub const PLATFORM_PROFILE: DefaultPlatformProfile = DefaultPlatformProfile::P384;
    pub fn new_crypto() -> caliptra_dpe_crypto::RustCryptoImpl {
        caliptra_dpe_crypto::RustCryptoImpl::new_ecc384()
    }
}

#[cfg(feature = "ml-dsa")]
mod profile {
    use super::*;
    pub use caliptra_dpe::commands::CertifyKeyMldsa87Cmd as CertifyKeyCmd;
    pub const DPE_PROFILE: caliptra_dpe::DpeProfile = caliptra_dpe::DpeProfile::Mldsa87;
    pub const PLATFORM_PROFILE: DefaultPlatformProfile = DefaultPlatformProfile::Mldsa87;
    pub fn new_crypto() -> caliptra_dpe_crypto::RustCryptoImpl {
        caliptra_dpe_crypto::RustCryptoImpl::new_mldsa87()
    }
}

pub struct ToolsEnv<'a> {
    pub crypto: &'a mut dyn CryptoSuite,
    pub platform: &'a mut dyn Platform,
    pub state: &'a mut caliptra_dpe::State,
}

impl DpeEnv for ToolsEnv<'_> {
    fn crypto(&mut self) -> &mut dyn CryptoSuite {
        self.crypto
    }
    fn platform(&mut self) -> &mut dyn Platform {
        self.platform
    }
    fn state(&mut self) -> &mut caliptra_dpe::State {
        self.state
    }
    fn get(&mut self) -> (&mut dyn CryptoSuite, &mut dyn Platform, &mut caliptra_dpe::State) {
        (self.crypto, self.platform, self.state)
    }
}

pub struct TestTypes {}

// Call DeriveContext on the default context so the generated cert will have a
// TcbInfo populated.
fn add_tcb_info(
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    data: &TciMeasurement,
    tci_type: u32,
    svn: u32,
) {
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: *data,
        flags: DeriveContextFlags::INPUT_ALLOW_X509 | DeriveContextFlags::MAKE_DEFAULT,
        tci_type,
        target_locality: 0, // Unused since flag isn't set
        svn,
    };
    let cmd_body = cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(caliptra_dpe::commands::Command::DERIVE_CONTEXT)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    let _ = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::DeriveContext(res) => res,
        Response::Error(res) => panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };
}

fn certify_key(dpe: &mut DpeInstance, env: &mut dyn DpeEnv, format: u32) -> Vec<u8> {
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        label: [0; DPE_PROFILE.hash_size()],
        format,
    };
    let cmd_body = certify_key_cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(caliptra_dpe::commands::Command::CERTIFY_KEY)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    let certify_key_response = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::CertifyKey(res) => res,
        Response::Error(res) => panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };

    certify_key_response.cert().unwrap().to_vec()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(value_enum, default_value_t = Format::X509)]
    format: Format,

    #[arg(long)]
    critical: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    X509,
    Csr,
}

fn main() {
    let args = Args::parse();

    let (format, format_str) = match args.format {
        Format::X509 => (commands::CertifyKeyCommand::FORMAT_X509, "CERTIFICATE"),
        Format::Csr => (commands::CertifyKeyCommand::FORMAT_CSR, "PKCS7"),
    };

    let support = Support::AUTO_INIT | Support::X509 | Support::CSR;
    let flags = if args.critical {
        DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL
    } else {
        DpeFlags::empty()
    };

    let mut crypto = profile::new_crypto();
    let mut platform = DefaultPlatform(PLATFORM_PROFILE);
    let mut state = caliptra_dpe::State::new(support, flags);
    let mut env = ToolsEnv {
        crypto: &mut crypto,
        platform: &mut platform,
        state: &mut state,
    };

    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    add_tcb_info(
        &mut dpe,
        &mut env,
        &TciMeasurement::default(),
        u32::from_be_bytes(*b"TEST"),
        0,
    );
    let cert = certify_key(&mut dpe, &mut env, format);

    let pem = Pem::new(format_str, cert);

    print!(
        "{}",
        encode_config(
            &pem,
            EncodeConfig {
                line_ending: LineEnding::LF
            }
        )
    );
}
