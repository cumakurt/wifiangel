"""Session logging and report path helpers."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from config.defaults import LOGS_ROOT
from reports import generate_security_report


class Logger:
    def __init__(self) -> None:
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = LOGS_ROOT / self.timestamp
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.main_log = self.log_dir / "main.log"
        self.attack_log = self.log_dir / "attacks.log"
        self.network_log = self.log_dir / "networks.log"
        self.client_log = self.log_dir / "clients.log"
        self.evil_twin_log = self.log_dir / "evil_twin.log"
        self.dns_log = self.log_dir / "dns_queries.log"
        self.traffic_log = self.log_dir / "traffic.log"

        self.logger = logging.getLogger("WiFiAngel")
        self.logger.setLevel(logging.INFO)

        detailed_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        attack_formatter = logging.Formatter("%(asctime)s - %(attack_type)s - %(message)s")
        network_formatter = logging.Formatter("%(asctime)s - %(network)s - %(message)s")
        client_formatter = logging.Formatter("%(asctime)s - %(client)s - %(message)s")
        evil_twin_formatter = logging.Formatter("%(asctime)s - %(evil_twin)s - %(message)s")
        dns_formatter = logging.Formatter("%(asctime)s - %(client_ip)s - %(query)s - %(type)s")
        traffic_formatter = logging.Formatter(
            "%(asctime)s - %(src)s - %(dst)s - %(bytes)s - %(protocol)s"
        )

        self.main_handler = logging.FileHandler(self.main_log)
        self.main_handler.setFormatter(detailed_formatter)

        self.attack_handler = logging.FileHandler(self.attack_log)
        self.attack_handler.setFormatter(attack_formatter)

        self.network_handler = logging.FileHandler(self.network_log)
        self.network_handler.setFormatter(network_formatter)

        self.client_handler = logging.FileHandler(self.client_log)
        self.client_handler.setFormatter(client_formatter)

        self.evil_twin_handler = logging.FileHandler(self.evil_twin_log)
        self.evil_twin_handler.setFormatter(evil_twin_formatter)

        self.dns_handler = logging.FileHandler(self.dns_log)
        self.dns_handler.setFormatter(dns_formatter)

        self.traffic_handler = logging.FileHandler(self.traffic_log)
        self.traffic_handler.setFormatter(traffic_formatter)

        self.logger.addHandler(self.main_handler)

        self.attack_logger = logging.getLogger("WiFiAngel.Attacks")
        self.attack_logger.setLevel(logging.INFO)
        self.attack_logger.addHandler(self.attack_handler)

        self.network_logger = logging.getLogger("WiFiAngel.Networks")
        self.network_logger.setLevel(logging.INFO)
        self.network_logger.addHandler(self.network_handler)

        self.client_logger = logging.getLogger("WiFiAngel.Clients")
        self.client_logger.setLevel(logging.INFO)
        self.client_logger.addHandler(self.client_handler)

        self.evil_twin_logger = logging.getLogger("WiFiAngel.EvilTwin")
        self.evil_twin_logger.setLevel(logging.INFO)
        self.evil_twin_logger.addHandler(self.evil_twin_handler)

        self.dns_logger = logging.getLogger("WiFiAngel.DNS")
        self.dns_logger.setLevel(logging.INFO)
        self.dns_logger.addHandler(self.dns_handler)

        self.traffic_logger = logging.getLogger("WiFiAngel.Traffic")
        self.traffic_logger.setLevel(logging.INFO)
        self.traffic_logger.addHandler(self.traffic_handler)

    def log_attack(self, attack_type: str, message: str, **kwargs):
        extra = {"attack_type": attack_type}
        extra.update(kwargs)
        self.attack_logger.info(message, extra=extra)
        self.info(f"Attack: {attack_type} - {message}")

    def log_network(self, network_ssid: str, message: str, **kwargs):
        extra = {"network": network_ssid}
        extra.update(kwargs)
        self.network_logger.info(message, extra=extra)
        self.info(f"Network: {network_ssid} - {message}")

    def log_client(self, client_mac: str, message: str, **kwargs):
        extra = {"client": client_mac}
        extra.update(kwargs)
        self.client_logger.info(message, extra=extra)
        self.info(f"Client: {client_mac} - {message}")

    def log_evil_twin(self, message: str, **kwargs):
        extra = {"evil_twin": kwargs.get("ssid", "Unknown")}
        extra.update(kwargs)
        self.evil_twin_logger.info(message, extra=extra)
        self.info(f"Evil Twin: {message}")

    def log_dns_query(self, client_ip: str, query: str, query_type: str):
        extra = {
            "client_ip": client_ip,
            "query": query,
            "type": query_type,
        }
        self.dns_logger.info(f"DNS Query: {query}", extra=extra)

    def log_traffic(self, src: str, dst: str, bytes_count: str, protocol: str):
        extra = {
            "src": src,
            "dst": dst,
            "bytes": bytes_count,
            "protocol": protocol,
        }
        self.traffic_logger.info(f"Traffic: {src} -> {dst}", extra=extra)

    def info(self, msg: object, *args: object, **kwargs: Any) -> None:
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: object, *args: object, **kwargs: Any) -> None:
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: object, *args: object, **kwargs: Any) -> None:
        self.logger.error(msg, *args, **kwargs)

    def debug(self, msg: object, *args: object, **kwargs: Any) -> None:
        self.logger.debug(msg, *args, **kwargs)

    def generate_report(self) -> Path:
        return generate_security_report(self.log_dir, self.timestamp)
