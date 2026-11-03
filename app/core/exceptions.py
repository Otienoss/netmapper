"""NetMapper temel istisnaları.

Tüm hatalar NetMapperError'dan türer; API katmanı bunları yakalayıp
kullanıcıya anlamlı HTTP durum kodları dönmek için kullanabilir.
"""


class NetMapperError(Exception):
    """Tüm NetMapper hatalarının temel sınıfı."""


class ScannerError(NetMapperError):
    """Bir tarayıcı (netdiscover/nmap) başarısız olduğunda ya da
    binary bulunamadığında fırlatılır."""


class ParseError(NetMapperError):
    """Ham araç çıktısı (nmap XML / netdiscover tablosu) normalize
    edilemediğinde fırlatılır."""


class JobNotFoundError(NetMapperError):
    """İstenen job_id sistemde bulunamadığında."""


class StorageError(NetMapperError):
    """Veritabanı işlemi başarısız olduğunda."""
