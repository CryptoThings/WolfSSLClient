
#include <sys/types.h>
#include <sys/time.h>

#include "certs.h"

#include "Entropy.h"
#include <TimeLib.h>
#include <EEPROM.h>

#include <WolfSSLClient.h>

#include <WiFi101.h>
#include <WiFiUdp.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha512.h"

#ifdef CORE_TEENSY
  #define WINC_IRQ  15
  #define WINC_CS   17
  #define WINC_EN   16
  #define WINC_RST  14
#else
  #define WINC_CS   8
  #define WINC_IRQ  7
  #define WINC_RST  4
  #define WINC_EN   2
#endif

WiFiClient client;

WolfSSLClient wssl;

WolfSSLCertConst verify_buffer(AWS_ROOT_CA_DER, sizeof(AWS_ROOT_CA_DER),
                               SSL_FILETYPE_ASN1);

void ntp_set_time();

// https://www.ssllabs.com/ssltest/viewMyClient.html
// https://www.howsmyssl.com/a/check

//char server[] = "www.google.com";    // name address for Google (using DNS)
//char server[] = "a21wtlfjxarim7.iot.us-west-2.amazonaws.com";
//char server[] = "www.howsmyssl.com";
//char server[] = "www.amazon.com";
//char server[] = "wiki.openssl.org";
char server[] = "www.ssllabs.com";
//char server[] = "www.cnn.com";

extern "C"
void Logging_cb(const int logLevel, const char *const logMessage)
{
  Serial.print("WL ");
  Serial.print(logLevel);
  Serial.print(": ");
  Serial.println(logMessage);
  Serial.flush();
}

void setup()
{
  char ssid[32] = ""; // network SSID
  char pass[64] = ""; // WPA Password

//  Sha384 sha384;
//  wc_InitSha384(&sha384);

  pinMode(WINC_EN, OUTPUT);
  digitalWrite(WINC_EN, HIGH);
  WiFi.setPins(WINC_CS, WINC_IRQ, WINC_RST);

  Entropy.Initialize();

  Serial.begin(9600);

  while (!Serial) { delay(100); }

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);

    WiFi.begin(ssid, pass);

    // wait 60 seconds for connection:
    uint8_t timeout = 60;
    while (timeout && (WiFi.status() != WL_CONNECTED)) {
      timeout--;
      delay(1000);
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("Connected to wifi");
    } else {
      // start over
    }
  }

  ntp_set_time();

  if (!wssl.init(client)) {
    Serial.println("Crypto init failed");
    return;
  }

  wolfSSL_SetLoggingCb(Logging_cb);
//  wolfSSL_Debugging_ON();

  wssl.set_verify_none();
//  wssl.set_root_cert(verify_buffer);

  Serial.println("\nStarting connection to server...");
  // if you get a connection, report back via serial:
//  IPAddress local(192, 168, 1, 3);
//  IPAddress local(104,196,190,195);
  if (wssl.connect(server, 443)) {
    Serial.println("connected to server");
    // Make a HTTP request:
    wssl.println("GET /ssltest/viewMyClient.html HTTP/1.1");
//    wssl.println("GET /a/check HTTP/1.1");
    wssl.print("Host: ");
    wssl.println(server);
    wssl.println("Connection: close");
    wssl.println();
  } else {
    Serial.println("connect failed");
    while (1) {}
  }
}

void loop() {
  // if there are incoming bytes available
  // from the server, read them and print them:
  while (wssl.available() > 0) {
    char c = wssl.read();
    Serial.write(c);
  }

  // if the server's disconnected, stop the wssl:
  if (!wssl.connected()) {
    Serial.println();
    Serial.println("disconnecting from server.");
    wssl.stop();

    // do nothing forevermore:
    while (true);
  }
}


// NTP time stamp is in the first 48 bytes of the message
const int NTP_PACKET_SIZE = 48;

// send an NTP request to the time server at the given address
static void sendNTPpacket(WiFiUDP &Udp, IPAddress& address, byte *packetBuffer)
{
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  Udp.beginPacket(address, 123); //NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}

void ntp_set_time()
{
  WiFiUDP Udp;
  byte packetBuffer[ NTP_PACKET_SIZE];
  unsigned int localPort = 2390;      // local port to listen for UDP packets
  IPAddress timeServer(129, 6, 15, 28); // time.nist.gov NTP server
  uint32_t t;
  int tx_count;

  Udp.begin(localPort);

  for (tx_count = 0; !Udp.available() && (tx_count < 5); tx_count++) {
    // send an NTP packet to a time server
    sendNTPpacket(Udp, timeServer, packetBuffer);
    // wait to see if a reply is available
    t = millis();
    while (!Udp.available() && ((millis() - t) < 1000)) {
      delay(50);
      Udp.parsePacket();
    }
  }
  if ( Udp.parsePacket() ) {
    // We've received a packet, read the data from it
    Udp.read(packetBuffer, NTP_PACKET_SIZE); // read the packet into the buffer

    //the timestamp starts at byte 40 of the received packet and is four bytes,
    // or two words, long. First, esxtract the two words:

    unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
    unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
    // combine the four bytes (two words) into a long integer
    // this is NTP time (seconds since Jan 1 1900):
    unsigned long secsSince1900 = highWord << 16 | lowWord;

    // now convert NTP time into everyday time:
    Serial.print("Set time = ");
    // Unix time starts on Jan 1 1970. In seconds, that's 2208988800:
    const unsigned long seventyYears = 2208988800UL;
    // subtract seventy years:
    unsigned long epoch = secsSince1900 - seventyYears;
    // print Unix time:
    Serial.println(epoch);

    setTime(epoch);
  }

  Udp.stop();
}

