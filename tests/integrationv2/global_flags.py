# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# We support global configuration flags that are set via command line.
# These flags enable Providers and Tests to determine how to behave
# based on the environment.

# If S2N is operating in FIPS mode
S2N_FIPS_MODE = "s2n_fips_mode"

# The version of provider being used
# (set from the S2N_LIBCRYPTO env var, which is how the original integration test works)
S2N_PROVIDER_VERSION = "s2n_provider_version"

_flags = {}


def get_flag(name, default=None):
    """Return the value of a flag"""
    return _flags.get(name, default)


def set_flag(name, value):
    """Set the value of a flag"""
    _flags[name] = value
