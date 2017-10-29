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

#include "Arduino.h"
#include "WolfSSLClient.h"

#ifdef CORE_TEENSY
#include "Entropy.h"
#endif
#include <TimeLib.h>
#include <sys/time.h>

/*
extern "C"
void Logging_cb(const int logLevel, const char *const logMessage);

static char g_print_buf[80];

#define T_PRINTF(...)    \
{ \
  snprintf(g_print_buf, 80, __VA_ARGS__); \
  Serial.print(g_print_buf); \
  Serial.flush(); \
}
*/
#define T_PRINTF(...)

WolfSSLClient::WolfSSLClient()
{
  init_ok = false;
  net_client = NULL;

  ctx = NULL;
  ssl = NULL;
  method = NULL;
  timeout_ms = 3000;

  m_root_cert = NULL;
  m_cert_chain = NULL;
  m_cert = NULL;
  m_private_key = NULL;

  m_ecc_sign_cb = NULL;
  m_ecc_sign_ctx = NULL;
  m_ecc_verify_cb = NULL;
  m_ecc_verify_ctx = NULL;
  m_ecc_pms_cb = NULL;
  m_ecc_pms_ctx = NULL;
  m_verify_peer = SSL_VERIFY_NONE;
}

WolfSSLClient::WolfSSLClient(Client &_net)
{
  WolfSSLClient();
  setClient(_net);
}

void WolfSSLClient::setClient(Client &net)
{
  net_client = &net;
}

bool WolfSSLClient::init(Client &net)
{
  setClient(net);
  return init();
}

bool WolfSSLClient::init()
{
#ifdef CORE_TEENSY
  Entropy.Initialize();
#endif

  if (net_client == NULL)
    return false;

  method = wolfTLSv1_2_client_method();
  if (method == NULL) {
    return false;
  }
  ctx = wolfSSL_CTX_new(method);
  if (ctx == NULL) {
    return false;
  }
  wolfSSL_SetIOSend(ctx, WolfSSLClient::ClientSend);
  wolfSSL_SetIORecv(ctx, WolfSSLClient::ClientReceive);

  wolfSSL_CTX_set_verify(ctx, m_verify_peer, NULL);

  wolfSSL_CTX_SetEccSignCb(ctx, m_ecc_sign_cb);
  wolfSSL_CTX_SetEccVerifyCb(ctx, m_ecc_verify_cb);
  wolfSSL_CTX_SetEccPmsCb(ctx, m_ecc_pms_cb);

  init_ok = true;

  T_PRINTF("WolfSSLClient::init OK ok @%d\n", __LINE__);
  return true;
}

int WolfSSLClient::connect(IPAddress ip, uint16_t port)
{
  if (!init_ok) {
    return 0;
  }
  if (net_client != NULL) {
    if (!net_client->connect(ip, port)) {
      return 0;
    }
    if (!ssl_connect()) {
      net_client->stop();
      return 0;
    }
  }
  return 1;
}

int WolfSSLClient::connect(const char *host, uint16_t port)
{
  if (!init_ok) {
    return 0;
  }
  if (net_client != NULL) {
    if (!net_client->connect(host, port)) {
      return 0;
    }
    if (!ssl_connect()) {
      net_client->stop();
      return 0;
    }
  }
  return 1;
}

int WolfSSLClient::load_certificates()
{
  int ret;
  last_error = 0;

  if (m_root_cert != NULL) {
    if (m_root_cert->have_cert()) {
      ret = wolfSSL_CTX_load_verify_buffer(ctx, m_root_cert->data(),
              m_root_cert->size(), m_root_cert->type());
      m_root_cert->done();
      if (ret != SSL_SUCCESS) {
        last_error = ret;
        return false;
      }
    }
  }
  if (m_cert_chain != NULL) {
    if (m_cert_chain->have_cert()) {
      ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, m_cert_chain->data(),
              m_cert_chain->size());
      m_cert_chain->done();
      if (ret != SSL_SUCCESS) {
        last_error = ret;
        return false;
      }
    }
  }
  if (m_cert != NULL) {
    if (m_cert->have_cert()) {
      ret = wolfSSL_CTX_use_certificate_buffer(ctx, m_cert->data(),
              m_cert->size(), m_cert->type());
      m_cert->done();
      if (ret != SSL_SUCCESS) {
        last_error = ret;
        return false;
      }
    }
  }
  if (m_private_key != NULL) {
    if (m_private_key->have_cert()) {
      ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, m_private_key->data(),
              m_private_key->size(), m_private_key->type());
      m_private_key->done();
      if (ret != SSL_SUCCESS) {
        last_error = ret;
        return false;
      }
    }
  }
  return 1;
}

void WolfSSLClient::SetEccSignCb(CallbackEccSign cb, void *_ctx)
{
  m_ecc_sign_cb = cb;
  m_ecc_sign_ctx = _ctx;
  if (init_ok) { 
    if (ctx != NULL)
      wolfSSL_CTX_SetEccSignCb(ctx, cb);
    if (ssl != NULL)
      wolfSSL_SetEccSignCtx(ssl, _ctx);
  }
}

void WolfSSLClient::SetEccVerifyCb(CallbackEccVerify cb, void *_ctx)
{
  m_ecc_verify_cb = cb;
  m_ecc_verify_ctx = _ctx;
  if (init_ok) { 
    if (ctx != NULL)
      wolfSSL_CTX_SetEccVerifyCb(ctx, cb);
    if (ssl != NULL)
      wolfSSL_SetEccVerifyCtx(ssl, _ctx);
  }
}

void WolfSSLClient::SetEccPmsCb(CallbackEccPms cb, void *_ctx)
{
  m_ecc_pms_cb = cb;
  m_ecc_pms_ctx = _ctx;
  if (init_ok) { 
    if (ctx != NULL)
      wolfSSL_CTX_SetEccPmsCb(ctx, cb);
    if (ssl != NULL)
      wolfSSL_SetEccPmsCtx(ssl, _ctx);
  }
}

int WolfSSLClient::ssl_connect()
{
  // load certificates just before connecting
  if (!load_certificates()) {
    return 0;
  }

  ssl = wolfSSL_new(ctx);
  if (ssl == NULL) {
    return 0;
  }
  wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_9);

  wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);

  wolfSSL_SetIOReadCtx(ssl, this);
  wolfSSL_SetIOWriteCtx(ssl, this);

  wolfSSL_SetEccSignCtx(ssl, m_ecc_sign_ctx);
  wolfSSL_SetEccVerifyCtx(ssl, m_ecc_verify_ctx);
  wolfSSL_SetEccPmsCtx(ssl, m_ecc_pms_ctx);

  if (wolfSSL_negotiate(ssl) != SSL_SUCCESS)
    return 0;

  return 1;
}

size_t WolfSSLClient::write(uint8_t b)
{
  return (write(&b, 1));
}

size_t WolfSSLClient::write(const uint8_t *buf, size_t size)
{
  int ret;

  ret = wolfSSL_write(ssl, buf, size);
  last_error = wolfSSL_get_error(ssl, 0);

  if (last_error == SSL_ERROR_WANT_WRITE) {
    ret = 0; /* Timeout */
  }
  T_PRINTF("ssl::write s %d r %d e %X\n", size, ret, last_error);

  return ret;
}

int WolfSSLClient::available()
{
  int s;
  uint8_t b;
  if (!connected())
    return -1;

  s = wolfSSL_pending(ssl);
  if (s > 0)
    return s;

  if (net_client->available() == 0) {
    return 0;
  }
  wolfSSL_peek(ssl, &b, 1);
  s = wolfSSL_pending(ssl);
  return (s);
}

int WolfSSLClient::read()
{
  uint8_t r;
  if (read(&r, 1) <= 0) {
    return -1;
  }
  return r;
}

int WolfSSLClient::read(uint8_t *buf, size_t size)
{
  int ret;

  ret = wolfSSL_read(ssl, buf, size);
  last_error = wolfSSL_get_error(ssl, 0);
  T_PRINTF("ssl::read s %d r %d e %X\n", size, ret, last_error);
  if (last_error == SSL_ERROR_WANT_READ) {
    ret = 0; /* Timeout */
  }
  return ret;
}

int WolfSSLClient::peek()
{
  int ret;
  uint8_t b;

  T_PRINTF("ssl::peek\n");
  if (!available())
    return -1;

  ret = wolfSSL_peek(ssl, &b, 1);
  if (ret == -1)
    return -1;

  return b;
}

void WolfSSLClient::flush()
{
  if (init_ok && (net_client != NULL))
    net_client->flush();
}

void WolfSSLClient::stop()
{
  if (!init_ok) {
    return;
  }
  if (ssl != NULL)
    wolfSSL_free(ssl);

  if (ctx != NULL)
    wolfSSL_CTX_free(ctx);

  wolfSSL_Cleanup();

  ssl = NULL;
  ctx = NULL;

  if (net_client != NULL)
    net_client->stop();

  init_ok = false;
}

uint8_t WolfSSLClient::connected()
{
  if (init_ok && (net_client != NULL))
    return net_client->connected();

  return 0;
}

WolfSSLClient::operator bool()
{
  if (init_ok && (net_client != NULL))
    return *net_client;

  return false;
}

void WolfSSLClient::set_debug(wolfSSL_Logging_cb log_function)
{
  wolfSSL_SetLoggingCb(log_function);
  wolfSSL_Debugging_ON();
}
#if 0
bool WolfSSLClient::set_root_cert(const uint8_t *cert, size_t sz, int cert_type)
{
  int ret;
  last_error = 0;
  if (!init_ok) {
    last_error = -10000;
    return false;
  }

  ret = wolfSSL_CTX_load_verify_buffer(ctx, cert, sz, cert_type);
  if (ret != SSL_SUCCESS) {
    last_error = ret;
    return false;
  }
  return true;
}

bool WolfSSLClient::set_cert_chain(const unsigned char *cert_chain, size_t sz)
{
  int ret;
  if (!init_ok) {
    last_error = -10000;
    return false;
  }

  ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, cert_chain, sz);
  if (ret != SSL_SUCCESS) {
    last_error = ret;
    return false;
  }
  return true;
}

bool WolfSSLClient::set_cert(const unsigned char *cert_chain, size_t sz, int cert_type)
{
  int ret;
  if (!init_ok) {
    last_error = -10000;
    return false;
  }

  ret = wolfSSL_CTX_use_certificate_buffer(ctx, cert_chain, sz, cert_type);
  if (ret != SSL_SUCCESS) {
    last_error = ret;
    return false;
  }
  return true;
}

bool WolfSSLClient::set_private_key(const uint8_t *key, size_t sz, int cert_type)
{
  int ret;
  if (!init_ok) {
    last_error = -10000;
    return false;
  }

  ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, sz, cert_type);
  if (ret != SSL_SUCCESS) {
    last_error = ret;
    return false;
  }
  return true;
}
#endif
void WolfSSLClient::set_verify_none()
{
  m_verify_peer = SSL_VERIFY_NONE;
  if (init_ok && (ctx != NULL))
    wolfSSL_CTX_set_verify(ctx, m_verify_peer, NULL);
}

void WolfSSLClient::set_verify_peer()
{
  m_verify_peer = SSL_VERIFY_PEER;
  if (init_ok && (ctx != NULL))
    wolfSSL_CTX_set_verify(ctx, m_verify_peer, NULL);
}

int WolfSSLClient::ClientSend(WOLFSSL* ssl, char* _msg, int sz, void* ctx)
{
  WolfSSLClient *ws = static_cast<WolfSSLClient*>(ctx);
  int sent;
  int ret = 0;

//  Serial.print("ClientSend start ");
//  Serial.println(sz);
//  Serial.flush();

  if (ws == NULL)
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;

  if (!ws->init_ok || (ws->net_client == NULL))
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;

  if (!ws->net_client->connected())
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;

  sent = 0;
  do {
    int to_send = (((sz - sent) > 256) ? 256 : (sz - sent));
    ret = ws->net_client->write((byte*)(_msg + sent), to_send);
    sent += ret;
  } while ((ret > 0) && (sent < sz));

  if ((ret == 0) && (sent == 0)) {
    sent = WOLFSSL_CBIO_ERR_WANT_WRITE;
  } else if (ret < 0) {
    sent = WOLFSSL_CBIO_ERR_GENERAL;
  }

//  Serial.print("ClientSend end ");
//  Serial.println(sent);
//  Serial.flush();
  return sent;
/*
  WOLFSSL_CBIO_ERR_WANT_WRITE
  WOLFSSL_CBIO_ERR_CONN_RST
  WOLFSSL_CBIO_ERR_ISR
  WOLFSSL_CBIO_ERR_CONN_CLOSE
*/
}

int WolfSSLClient::ClientReceive(WOLFSSL* ssl, char* reply, int sz, void* ctx)
{
  WolfSSLClient *ws = static_cast<WolfSSLClient*>(ctx);
  int ret = 0;
  uint32_t t = millis();
  ws->timeout_ms = 2000;

//  Serial.print("ClientReceive start ");
//  Serial.println(sz);
//  Serial.flush();

  if (ws == NULL)
    return WOLFSSL_CBIO_ERR_GENERAL;

  if (!ws->init_ok || (ws->net_client == NULL))
    return WOLFSSL_CBIO_ERR_GENERAL;

  if (!ws->net_client->connected())
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;

  ret = 0;
  while (((millis() - t) < ws->timeout_ms) && (ret < sz))
  {
    if (ws->net_client->available() > 0) 
      reply[ret++] = ws->net_client->read();
    delay(1);
  }

  if (ret > 0) {
//    Serial.print("ClientReceive end ");
//    Serial.println(ret);
//    Serial.flush();
  } else if ((ret == 0) && ((millis() - t) >= ws->timeout_ms)) {
    // timeout
    ret = WOLFSSL_CBIO_ERR_WANT_READ;
//    Serial.print("ClientReceive end timeout ");
//    Serial.println(ws->timeout_ms);
//    Serial.flush();
  } else if (ret < 0) {
//    Serial.print("ClientReceive end ERROR ");
//    Serial.println(ws->timeout_ms);
//    Serial.flush();
    ret = WOLFSSL_CBIO_ERR_GENERAL;
  }
  return ret;
/*
  WOLFSSL_CBIO_ERR_GENERAL
  WOLFSSL_CBIO_ERR_WANT_READ
  WOLFSSL_CBIO_ERR_CONN_RST
  WOLFSSL_CBIO_ERR_ISR
  WOLFSSL_CBIO_ERR_CONN_CLOSE
  WOLFSSL_CBIO_ERR_TIMEOUT
*/
}

extern "C"
int WolfSSL_GenerateSeed(uint8_t *output, uint32_t sz);

#ifdef CORE_TEENSY

__attribute__((weak))
int WolfSSL_GenerateSeed(uint8_t *output, uint32_t sz)
{
  uint32_t r = 0;
  do {
    while (Entropy.available()) {
      output[r++] = Entropy.random(255);
      if (r == sz) {
        return 0;
      }
    }
    delay(10);
  } while (1);
  return -1;
}
#else

__attribute__((weak))
int WolfSSL_GenerateSeed(uint8_t *output, uint32_t sz)
{
  uint32_t r = 0;
  do {
    output[r] = r;
    r++;
    if (r == sz) {
      return 0;
    }
  } while (1);
  return -1;
}
#endif

// TIME

extern "C"
time_t XTIME(time_t * timer)
{
  return now();
}

int _gettimeofday(struct timeval *tv, void *tzvp)
{
  tv->tv_sec = now();
  tv->tv_usec = 0;

  return 0;
}

