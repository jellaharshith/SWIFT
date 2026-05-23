"""v8.0 -- web3 grep patterns."""
from __future__ import annotations

from bounty.web3 import patterns


_SOL = """
pragma solidity ^0.8.0;
contract Demo {
    function pay(address payable to, uint256 amt) public {
        require(tx.origin == owner);
        (bool ok, ) = to.call{value: amt}("");
    }
    function loop(uint256[] memory xs) public pure returns (uint256 s) {
        for (uint256 i = 0; i < xs.length; i++) { s += xs[i]; }
    }
}
"""


def test_scan_picks_up_known_classes(tmp_path):
    f = tmp_path / "Demo.sol"
    f.write_text(_SOL, encoding="utf-8")
    findings = patterns.scan(str(f))
    names = {x["pattern"] for x in findings}
    assert "reentrancy_call" in names
    assert "tx_origin_auth" in names
    assert "unbounded_loop" in names


def test_directory_scan(tmp_path):
    (tmp_path / "a.sol").write_text(_SOL, encoding="utf-8")
    (tmp_path / "b.sol").write_text(_SOL, encoding="utf-8")
    findings = patterns.scan(str(tmp_path))
    files = {x["file"] for x in findings}
    assert len(files) == 2
