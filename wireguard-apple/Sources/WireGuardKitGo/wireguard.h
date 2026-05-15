/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

typedef void (*libxray_sockcallback)(uintptr_t fd, void* ctx);
extern char *LibXrayCutGeoData(const char *datDir, const char *dstDir, const char *cutCodePath);
extern char *LibXrayLoadGeoData(const char *datDir, const char *name, const char *geoType);
extern char *LibXrayPing(const char *datDir, const char *configPath, int timeout, const char *url, const char *proxy);
extern char *LibXrayQueryStats(const char *server, const char *dir);
extern char *LibXrayCustomUUID(const char *text);
extern char *LibXrayTestXray(const char *datDir, const char *configPath);
extern char *LibXrayRunXray(const char *datDir, const char *configPath, int64_t maxMemory);
extern char *LibXrayStopXray();
extern char *LibXrayXrayVersion();
extern char* LibXraySetSockCallback(libxray_sockcallback cb, void* ctx);

extern void StartProxy(const char *link, const char *peerAddrStr, const char *localAddrStr, int n, int udp);
extern void StopProxy(void);
extern void RestartProxy(void);
extern void ProxyForceReconnect(void);
extern void ProxySetLogger(void *context, logger_fn_t logger_fn);
extern int ProxyWaitReady(int timeoutMs);
extern void ProxySetRemoteCaptchaService(const char *url, const char *apiKey);

typedef void (*manual_captcha_cb_t)(const char *request_id, const char *redirect_uri);
extern void TurnBridgeSetManualCaptchaCallback(manual_captcha_cb_t cb);
extern void TurnBridgeSubmitManualCaptchaToken(const char *request_id, const char *token);
extern void TurnBridgeCancelManualCaptcha(const char *request_id, const char *reason);
extern void TurnBridgeSetManualCaptchaMode(int enabled);
extern void TurnBridgeSetStreamAggregation(int enabled);
extern void TurnBridgeSetCaptchaTrapDir(const char *path);
extern int TurnBridgeGetCaptchaDirectCount(void);
extern int TurnBridgeGetCaptchaTunnelCount(void);
extern int TurnBridgeGetCaptchaDirectAttempts(void);
extern int TurnBridgeGetCaptchaTunnelAttempts(void);
extern int TurnBridgeGetCaptchaDirectInFlight(void);
extern int TurnBridgeGetCaptchaTunnelInFlight(void);
extern int TurnBridgeIsCaptchaDirectSaturated(void);
extern int TurnBridgeIsCaptchaTunnelSaturated(void);
extern int TurnBridgeGetSessionsReady(void);
extern int TurnBridgeGetSessionsTarget(void);

#endif
