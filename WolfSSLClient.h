/*
 * Copyright (C) 2016-2017 Robert Totte
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __WOLFSSLCLIENT_H__
#define __WOLFSSLCLIENT_H__

#include "Client.h"
#include "IPAddress.h"

#include "wolfssl/wolfcrypt/settings.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>

class WolfSSLCertLoader {
public:
  WolfSSLCertLoader() {}
  virtual ~WolfSSLCertLoader() {}
  virtual bool have_cert() = 0;
  virtual const uint8_t *data() = 0;
  virtual size_t size() = 0;
  virtual int type() { return SSL_FILETYPE_PEM; }
  // cert loaded, free resources allocated in data() or have_cert()
  virtual void done() { }
};

class WolfSSLCertConst : public WolfSSLCertLoader {
protected:
  const uint8_t *m_cert;
  size_t m_sz;
  int m_cert_type;
public:
  WolfSSLCertConst(const uint8_t *cert, size_t sz,
        int cert_type = SSL_FILETYPE_PEM) :
    m_cert(cert), m_sz(sz), m_cert_type(cert_type)
  { }
  virtual bool have_cert() { return true; }
  virtual const uint8_t *data() { return m_cert; }
  virtual size_t size() { return m_sz; }
  virtual int type() { return m_cert_type; }
};

class WolfSSLClient : public Client {

public:
  WolfSSLClient();
  WolfSSLClient(Client &net);

  void setClient(Client &net);

  bool init();
  bool init(Client &net);

  virtual int connect(IPAddress ip, uint16_t port);
  virtual int connect(const char *host, uint16_t port);

  virtual size_t write(uint8_t);
  virtual size_t write(const uint8_t *buf, size_t size);

  virtual int available();

  virtual int read();
  virtual int read(uint8_t *buf, size_t size);

  virtual int peek();
  virtual void flush();
  virtual void stop();
  virtual uint8_t connected();

  virtual operator bool();

  void set_debug(wolfSSL_Logging_cb log_function);

// cert types: SSL_FILETYPE_PEM SSL_FILETYPE_ASN1
  void set_root_cert(WolfSSLCertLoader *c) { m_root_cert = c; }
  void set_root_cert(WolfSSLCertLoader &c) { m_root_cert = &c; }
  void set_cert_chain(WolfSSLCertLoader *c) { m_cert_chain  = c; }
  void set_cert_chain(WolfSSLCertLoader &c) { m_cert_chain  = &c; }
  void set_cert(WolfSSLCertLoader *c) { m_cert = c; }
  void set_cert(WolfSSLCertLoader &c) { m_cert = &c; }
  void set_private_key(WolfSSLCertLoader *c) { m_private_key = c; }
  void set_private_key(WolfSSLCertLoader &c) { m_private_key = &c; }

  void set_verify_none();
  void set_verify_peer();

  void SetEccSignCb(CallbackEccSign cb, void *c = NULL);
  void SetEccVerifyCb(CallbackEccVerify cb, void *c = NULL);
  void SetEccPmsCb(CallbackEccPms cb, void *c = NULL);

  int get_error() { return last_error; }

private:
  bool init_ok;
  uint32_t timeout_ms;
  int last_error;
  Client *net_client;

  WolfSSLCertLoader *m_root_cert;
  WolfSSLCertLoader *m_cert_chain;
  WolfSSLCertLoader *m_cert;
  WolfSSLCertLoader *m_private_key;

  int m_verify_peer;

  WOLFSSL_CTX* ctx;
  WOLFSSL* ssl;
  WOLFSSL_METHOD* method;

  CallbackEccSign m_ecc_sign_cb;
  void *m_ecc_sign_ctx;
  CallbackEccVerify m_ecc_verify_cb;
  void *m_ecc_verify_ctx;
  CallbackEccPms m_ecc_pms_cb;
  void *m_ecc_pms_ctx;

  int ssl_connect();
  int load_certificates();

  static int ClientSend(WOLFSSL* ssl, char* _msg, int sz, void* ctx);
  static int ClientReceive(WOLFSSL* ssl, char* reply, int sz, void* ctx);
};

#endif



