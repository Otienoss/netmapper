from app.normalization.netdiscover_parser import extract_ips, parse_netdiscover_output

SAMPLE_OUTPUT = """  IP            MAC Address        Count     Length    MAC Vendor / Hostname
------------------------------------------------------------------------------
  192.168.1.1   aa:bb:cc:00:00:01  1         60        TP-Link Technologies
  192.168.1.42  aa:bb:cc:00:00:02  2         60        Unknown Vendor

  192.168.1.42  aa:bb:cc:00:00:02  2         60        Unknown Vendor
"""


def test_parse_table_rows():
    hosts = parse_netdiscover_output(SAMPLE_OUTPUT)
    # tekrar eden satır ayıklanır, başlık/sınır satırları atılır
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.42"]
    first = hosts[0]
    assert first.mac == "aa:bb:cc:00:00:01"
    assert first.vendor == "TP-Link Technologies"
    assert first.source_tool == "netdiscover"
    assert hosts[1].vendor == "Unknown Vendor"


def test_parse_empty_output():
    assert parse_netdiscover_output("") == []
    assert parse_netdiscover_output(" hosts\r\n------\r\n") == []


def test_extract_ips_deduplicates_and_keeps_order():
    raw = "10.0.0.5 y\n10.0.0.1 z\n10.0.0.5 tekrar"
    assert extract_ips(raw) == ["10.0.0.5", "10.0.0.1"]
