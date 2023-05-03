import json
import shutil
import uuid
import subprocess
import os
import time
import tempfile
from statistics import median, mean, stdev
from threading import Thread
from abc import ABC, abstractmethod

import requests
from browserdebuggertools import ChromeInterface
from typing import List

_DIR = os.path.dirname(os.path.realpath(__file__))
_TMP = tempfile.gettempdir()


class _Runner(ABC, Thread):
    """
    Creates and manages a process
    """

    def __init__(self, name: str):
        super().__init__()
        self._name = name
        self._process = None

    @property
    @abstractmethod
    def port(self) -> int:
        ...

    @property
    @abstractmethod
    def _cmd(self) -> list:
        ...

    def run(self):
        self._process = subprocess.Popen(self._cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._process.communicate()

    def start(self):
        """
        Start the process and wait until we can communicate with it
        """
        super().start()
        start = time.time()
        while True:
            if (time.time() - start) > 10:
                raise Exception(f"Timed out waiting for {self._name} to start")
            time.sleep(2)
            try:
                return requests.get(f"http://localhost:{self.port}")
            except requests.ConnectionError:
                pass
            print(f"Waiting for {self._name} to start")

    def stop(self):
        """
        Terminate the process and wait for the exit code
        """
        if self._process:
            self._process.terminate()
            time.sleep(1)
            while self.is_alive():
                print(f"Waiting for {self._name} to stop")
                time.sleep(1)


class _ProxyRunner(_Runner):
    """
    Creates and manages an MITMProxy process
    """

    dump = os.path.join(_TMP, "dump.har")

    def __init__(self, patched: bool = False):
        super().__init__("proxy")
        self._process = None
        self._patched = patched

    @property
    def port(self) -> int:
        return 9091

    @property
    def _cmd(self) -> list:
        cmd = [
            f"mitmdump",
            "-s", os.path.join(_DIR, "har_dump.py"),
            "-p", str(self.port),
            "--set", f"hardump={self.dump}"
        ]
        if self._patched:
            cmd += [
                "-s", f"{_DIR}/connection_patch.py",
            ]
        return cmd


class _ChromeRunner(_Runner):
    """
    Creates and manages a Google Chrome process
    """

    def __init__(self, proxy_port: int = None):
        super().__init__("chrome")
        self._client = None
        self._proxy_port = proxy_port
        self._data_dir = os.path.join(_TMP, str(uuid.uuid4()))

    @property
    def _cmd(self) -> list:
        cmd = [
            "google-chrome-stable",  "--no-sandbox", "--disable-gpu", f"--remote-debugging-port={self.port}",
            "--no-default-browser-check", "--no-first-run", "--headless", "--remote-allow-origins=*",
            f"--user-data-dir={self._data_dir}", "--ignore-certificate-errors", "--proxy-bypass-list=<-loopback>"
        ]
        if self._proxy_port:
            cmd.append(f"--proxy-server=localhost:{self._proxy_port}")
        return cmd

    @property
    def port(self) -> int:
        return 9222

    @property
    def client(self) -> ChromeInterface:
        if not self._client:
            self._client = ChromeInterface(self.port, domains={"Page": {}, "Network": {}})
        return self._client

    def stop(self):
        self.client.execute("Storage", "clearDataForOrigin", {
            "origin": "*", "storageTypes": "all"
        })
        self.client.execute("Network", "clearBrowserCache")
        self.client.quit()
        super().stop()
        shutil.rmtree(self._data_dir)


def _get_results(proxied: bool = False, patched: bool = False) -> List[float]:
    """
    Load a test page 5 times and capture the connect time for every request
    :param proxied: True if a proxy should be used
    :param patched: if True then patch the proxy
    :return: a list of connect times
    """
    proxy, chrome = None, None
    results = []
    count = 5

    for i in range(count):
        print(f"Collecting sample {i + 1}/{count}")
        try:
            if proxied:
                proxy = _ProxyRunner(patched=patched)
                proxy.start()
            chrome = _ChromeRunner(proxy.port if proxy else None)
            chrome.start()
            chrome.client.navigate("http://localhost")
            time.sleep(1)
            while chrome.client.get_document_readystate() != "complete":
                print("Waiting for ready state complete")
                time.sleep(1)
            chrome.client.stop_page_load()
            if not proxied:
                for event in chrome.client.get_events("Network", clear=True):
                    if (
                        event["method"] == "Network.responseReceived" and
                        event["params"]["response"]["url"].startswith("http")
                    ):
                        timing = event["params"]["response"].get("timing")
                        if timing and timing["connectEnd"] > -1:
                            results.append(timing["connectEnd"] - timing["connectStart"])

        finally:
            if chrome:
                chrome.stop()
            if proxy:
                proxy.stop()

        if proxied:
            with open(proxy.dump) as f:
                har = json.load(f)
            results += [
                entry['timings']['connect'] for entry in har['log']['entries'] if entry['timings']['connect'] > -1
            ]
            os.remove(proxy.dump)

    return results


def _prepare():
    """
    Create the resources to simulate loading a real world web page
    - For the given page, load 5 resources, for each of 5 different hosts.
    """
    num_resources, num_resources_per_origins = 5, 5
    for x in range(num_resources):
        with open(f"/var/www/html/script{x}.js", "w") as f:
            f.write(f"var x{x} = 'foo bar';")
    for x in range(num_resources_per_origins):
        with open("/etc/hosts", "a") as f:
            f.write(f"\n127.0.0.1 mitmproxy-testing{x}")
    inner = ""
    for i in range(num_resources_per_origins):
        for j in range(num_resources):
            inner += f"<script src=\"http://mitmproxy-testing{j}/script{i}.js\"></script>"
    html = f"<html><body>{inner}</body></html>"
    with open("/var/www/html/index.html", "w") as f:
        f.write(html)


def _print_results(title, results):
    print(title.capitalize())
    print(f"\t Count: {len(results): .0f}")
    print(f"\t Total: {sum(results): .0f}")
    print(f"\t Min: {min(results): .3f}")
    print(f"\t Median: {median(results): .3f}")
    print(f"\t Mean: {mean(results): .3f}")
    print(f"\t Max: {max(results): .3f}")
    print(f"\t Std Dev: {stdev(results): .3f}")


def main():
    _prepare()

    # Configure the loopback device for typical UK desktop user speeds
    subprocess.Popen(["tcset", "lo", "--delay", "10ms", "--overwrite", "--rate", "32Mbps"])
    print("GATHERING CONNECT TIME STATS")
    print("Collecting no proxy results")
    no_proxy_results = _get_results(proxied=False)
    print("Collecting unpatched proxied results")
    unpatched_proxied_results = _get_results(proxied=True)
    print("Collecting patched proxied results")
    patched_proxied_results = _get_results(proxied=True, patched=True)

    _print_results("No Proxy Results", no_proxy_results)
    _print_results("Unpatched Proxied Results", unpatched_proxied_results)
    _print_results("Patched Proxied Results", patched_proxied_results)


if __name__ == "__main__":
    main()
