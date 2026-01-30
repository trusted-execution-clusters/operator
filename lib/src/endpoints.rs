// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub const TRUSTEE_SERVICE: &str = "kbs-service";
pub const TRUSTEE_DEPLOYMENT: &str = "trustee-deployment";
pub const TRUSTEE_PORT: i32 = 8080;
pub const REGISTER_SERVER_SERVICE: &str = "register-server";
pub const REGISTER_SERVER_DEPLOYMENT: &str = "register-server";
pub const REGISTER_SERVER_PORT: i32 = 8000;
pub const ATTESTATION_KEY_REGISTER_SERVICE: &str = "attestation-key-register";
pub const ATTESTATION_KEY_REGISTER_DEPLOYMENT: &str = "attestation-key-register";
pub const ATTESTATION_KEY_REGISTER_PORT: i32 = 8001;

pub const REGISTER_SERVER_RESOURCE: &str = "ignition-clevis-pin-trustee";
pub const ATTESTATION_KEY_REGISTER_RESOURCE: &str = "register-ak";
