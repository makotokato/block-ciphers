//! Check all target requirements.
#[cfg(not(all(target_arch = "aarch64", target_endian = "little")))]
compile_error!("crate can only be used on aarch64 architectures");

#[cfg(not(target_feature = "crypto"))]
compile_error!(
    "enable crypto target features, e.g. with \
     RUSTFLAGS=\"-C target-feature=+crypto\" enviromental variable."
);
