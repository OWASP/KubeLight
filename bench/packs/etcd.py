import os
from bench.rule import CISRule
from bench.utils import have_flag, have_env


class CIS_2_1(CISRule):
    def scan(self):
        cert_val = self.etcd_bin.param_val("--cert-file") or have_env("ETCD_CERT_FILE")
        key_val = self.etcd_bin.param_val("--key-file") or have_env("ETCD_KEY_FILE")
        self.flag = bool(cert_val) and bool(key_val)


class CIS_2_2(CISRule):
    def scan(self):
        values = self.etcd_bin.param_val("--client-cert-auth") or have_env("ETCD_CLIENT_CERT_AUTH")
        self.flag = have_flag("true", values)


class CIS_2_3(CISRule):
    def scan(self):
        values = self.etcd_bin.param_val("--auto-tls") or have_env("ETCD_AUTO_TLS")
        self.flag = not bool(values) or have_flag("false", values)


class CIS_2_4(CISRule):
    def scan(self):
        cert_val = self.etcd_bin.param_val("--peer-cert-file") or have_env("ETCD_PEER_CERT_FILE")
        key_val = self.etcd_bin.param_val("--peer-key-file") or have_env("ETCD_PEER_KEY_FILE")
        self.flag = bool(cert_val) and bool(key_val)


class CIS_2_5(CISRule):
    def scan(self):
        values = self.etcd_bin.param_val("--peer-client-cert-auth") or have_env("ETCD_PEER_CLIENT_CERT_AUTH")
        self.flag = have_flag("true", values)


class CIS_2_6(CISRule):
    def scan(self):
        values = self.etcd_bin.param_val("--peer-auto-tls") or have_env("ETCD_PEER_AUTO_TLS")
        self.flag = not bool(values) or have_flag("false", values)


class CIS_2_7(CISRule):
    def scan(self):
        values = self.etcd_bin.param_val("--trusted-ca-file") or have_env("ETCD_TRUSTED_CA_FILE")
        self.flag = have_flag("true", values)
